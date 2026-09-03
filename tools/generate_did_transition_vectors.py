#!/usr/bin/env python3
"""Generate deterministic DID transition fixtures.

The fixed private seeds below are test-only material. They MUST NOT be used by
applications and are intentionally kept out of the generated JSON fixtures.
"""

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import ed25519

from anp.authentication.did_wba import (
    _ed25519_public_key_to_multibase,
    compute_multikey_fingerprint,
)
from anp.proof import (
    CRYPTOSUITE_EDDSA_JCS_2022,
    PROOF_TYPE_DATA_INTEGRITY,
    generate_w3c_proof,
)


ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "testdata" / "did_transition"
DOCUMENTS = OUTPUT / "documents"
CREATED = "2026-08-25T00:00:00Z"


def key(label: str) -> ed25519.Ed25519PrivateKey:
    seed = hashlib.sha256(f"anp-did-transition-test-only:{label}".encode()).digest()
    return ed25519.Ed25519PrivateKey.from_private_bytes(seed)


KEYS = {name: key(name) for name in ("old", "new", "newer", "other", "recovery", "late")}


def did_for(subject: str, key_name: str, *, origin: str = "example.com") -> str:
    fingerprint = compute_multikey_fingerprint(KEYS[key_name].public_key())
    return f"did:wba:{origin}:users:{subject}:e1_{fingerprint}"


OLD_DID = did_for("alice", "old")
NEW_DID = did_for("alice", "new")
NEWER_DID = did_for("alice", "newer")
OTHER_DID = did_for("bob", "other")
PORT_ORIGIN = "example.com%3A8443"
PORT_OLD_DID = did_for("alice", "old", origin=PORT_ORIGIN)
PORT_NEW_DID = did_for("alice", "new", origin=PORT_ORIGIN)


def vm(did: str, fragment: str, key_name: str) -> dict:
    return {
        "id": f"{did}#{fragment}",
        "type": "Multikey",
        "controller": did,
        "publicKeyMultibase": _ed25519_public_key_to_multibase(KEYS[key_name].public_key()),
    }


def unsigned_active(did: str, key_name: str, *, recovery: str | None = None) -> dict:
    binding = vm(did, "key-1", key_name)
    methods = [binding]
    assertions = [binding["id"]]
    if recovery:
        recovery_method = vm(did, "recovery-1", recovery)
        methods.append(recovery_method)
        assertions.append(recovery_method["id"])
    return {
        "@context": [
            "https://www.w3.org/ns/did/v1",
            "https://w3id.org/security/data-integrity/v2",
            "https://w3id.org/security/multikey/v1",
        ],
        "id": did,
        "verificationMethod": methods,
        "authentication": [binding["id"]],
        "assertionMethod": assertions,
    }


def sign(document: dict, key_name: str, verification_method: str) -> dict:
    return generate_w3c_proof(
        document,
        KEYS[key_name],
        verification_method,
        proof_purpose="assertionMethod",
        proof_type=PROOF_TYPE_DATA_INTEGRITY,
        cryptosuite=CRYPTOSUITE_EDDSA_JCS_2022,
        created=CREATED,
    )


def active(did: str, key_name: str, *, recovery: str | None = None) -> dict:
    document = unsigned_active(did, key_name, recovery=recovery)
    return sign(document, key_name, f"{did}#key-1")


def deactivated(
    trusted: dict,
    successor: str,
    signer: str | None,
    fragment: str = "key-1",
    *,
    add_method: tuple[str, str] | None = None,
) -> dict:
    document = copy.deepcopy(trusted)
    document.pop("proof", None)
    document["deactivated"] = True
    document["successorDid"] = successor
    if add_method:
        fragment_name, key_name = add_method
        method = vm(document["id"], fragment_name, key_name)
        document["verificationMethod"].append(method)
        document["assertionMethod"].append(method["id"])
    if signer is None:
        return document
    return sign(document, signer, f"{document['id']}#{fragment}")


def corrupt_proof_value(proof: dict) -> None:
    proof_value = proof["proofValue"]
    index = len(proof_value) // 2
    replacement = "A" if proof_value[index] != "A" else "B"
    proof["proofValue"] = proof_value[:index] + replacement + proof_value[index + 1 :]


def write_document(name: str, document: dict, documents: dict[str, str]) -> str:
    path = DOCUMENTS / f"{name}.json"
    path.write_text(json.dumps(document, indent=2, ensure_ascii=False) + "\n")
    documents[name] = f"documents/{name}.json"
    return documents[name]


def main() -> None:
    DOCUMENTS.mkdir(parents=True, exist_ok=True)
    documents: dict[str, str] = {}

    old_trusted = active(OLD_DID, "old", recovery="recovery")
    old_trusted_no_recovery = active(OLD_DID, "old")
    new_active = active(NEW_DID, "new", recovery="recovery")
    newer_active = active(NEWER_DID, "newer")
    newer_active = sign(
        {
            **{key: value for key, value in newer_active.items() if key != "proof"},
            "alsoKnownAs": [NEW_DID],
        },
        "newer",
        f"{NEWER_DID}#key-1",
    )
    other_active = active(OTHER_DID, "other")
    old_verified = deactivated(old_trusted, NEW_DID, "old")
    old_recovery = deactivated(old_trusted, NEW_DID, "recovery", "recovery-1")
    old_late_recovery = deactivated(
        old_trusted_no_recovery,
        NEW_DID,
        "late",
        "late-recovery",
        add_method=("late-recovery", "late"),
    )
    old_unsigned = deactivated(old_trusted, NEW_DID, None)
    old_bad_binding_proof = sign(old_unsigned, "old", f"{OLD_DID}#key-1")
    corrupt_proof_value(old_bad_binding_proof["proof"])
    new_recovery = deactivated(new_active, NEWER_DID, "recovery", "recovery-1")
    old_wrong_path = deactivated(old_trusted, OTHER_DID, "old")
    old_skip = deactivated(old_trusted, NEWER_DID, "old")
    new_cycle = deactivated(new_active, OLD_DID, "new")

    missing_proof = unsigned_active(NEW_DID, "new")
    bad_proof = copy.deepcopy(new_active)
    corrupt_proof_value(bad_proof["proof"])
    mismatch_did = did_for("alice", "other")
    mismatch = unsigned_active(mismatch_did, "new")
    mismatch = sign(mismatch, "new", f"{mismatch_did}#key-1")
    port_old_trusted = active(PORT_OLD_DID, "old")
    port_new_active = active(PORT_NEW_DID, "new")
    port_old_unsigned = deactivated(port_old_trusted, PORT_NEW_DID, None)

    fixture_values = {
        "old-trusted": old_trusted,
        "old-trusted-no-recovery": old_trusted_no_recovery,
        "new-active": new_active,
        "newer-active": newer_active,
        "other-active": other_active,
        "old-verified": old_verified,
        "old-recovery": old_recovery,
        "old-late-recovery": old_late_recovery,
        "old-unsigned": old_unsigned,
        "old-bad-binding-proof": old_bad_binding_proof,
        "port-old-trusted": port_old_trusted,
        "port-new-active": port_new_active,
        "port-old-unsigned": port_old_unsigned,
        "new-recovery": new_recovery,
        "old-wrong-path": old_wrong_path,
        "old-skip": old_skip,
        "new-cycle": new_cycle,
        "active-missing-proof": missing_proof,
        "active-bad-proof": bad_proof,
        "active-fingerprint-mismatch": mismatch,
    }
    for name, value in fixture_values.items():
        write_document(name, value, documents)

    def resolve_case(
        case_id: str,
        resolved: list[str],
        expected: dict,
        *,
        trusted: dict[str, str] | None = None,
        cache_edges: dict[str, str] | None = None,
        expected_cache_edges: dict[str, str] | None = None,
        max_hops: int = 8,
        current_hint: str | None = None,
        requested_did: str = OLD_DID,
    ) -> dict:
        case = {
            "id": case_id,
            "operation": "resolve_ignoring_hint" if current_hint is not None else "resolve",
            "requestedDid": requested_did,
            "trustedDocuments": trusted or {requested_did: documents["old-trusted"]},
            "resolvedDocuments": {
                fixture_values[name]["id"]: documents[name] for name in resolved
            },
            "cacheEdges": cache_edges or {},
            "expectedCacheEdges": expected_cache_edges or {},
            "maxHops": max_hops,
            "expected": expected,
        }
        if current_hint is not None:
            case["untrustedCurrentDidHint"] = current_hint
        return case

    provider_asserted_then_verified = resolve_case(
        "provider-asserted-cache-does-not-block-verified",
        ["old-verified", "new-active"],
        {"status": "superseded", "currentDid": NEW_DID, "hops": ["verified"], "assurance": "verified"},
        expected_cache_edges={OLD_DID: NEW_DID},
    )
    provider_asserted_then_verified["operation"] = "resolve_after_provider_asserted"
    provider_asserted_then_verified["preludeResolvedDocuments"] = {
        OLD_DID: documents["old-unsigned"],
        NEW_DID: documents["new-active"],
    }

    cases = [
        {
            "id": "active-e1-valid",
            "operation": "verify_active",
            "requestedDid": NEW_DID,
            "trustedDocuments": {},
            "resolvedDocuments": {NEW_DID: documents["new-active"]},
            "cacheEdges": {},
            "maxHops": 8,
            "expected": {"status": "active", "currentDid": NEW_DID, "hops": [], "assurance": None},
        },
        *[
            {
                "id": case_id,
                "operation": "verify_active",
                "requestedDid": fixture_values[name]["id"],
                "trustedDocuments": {},
                "resolvedDocuments": {fixture_values[name]["id"]: documents[name]},
                "cacheEdges": {},
                "maxHops": 8,
                "expected": {"error": "invalid_proof", "code": 1020},
            }
            for case_id, name in (
                ("active-e1-missing-proof", "active-missing-proof"),
                ("active-e1-bad-proof", "active-bad-proof"),
                ("active-e1-fingerprint-mismatch", "active-fingerprint-mismatch"),
            )
        ],
        resolve_case(
            "old-binding-verified",
            ["old-verified", "new-active"],
            {"status": "superseded", "currentDid": NEW_DID, "hops": ["verified"], "assurance": "verified"},
            expected_cache_edges={OLD_DID: NEW_DID},
        ),
        resolve_case(
            "preauthorized-recovery",
            ["old-recovery", "new-active"],
            {"status": "superseded", "currentDid": NEW_DID, "hops": ["recovery_verified"], "assurance": "recovery_verified"},
            expected_cache_edges={OLD_DID: NEW_DID},
        ),
        resolve_case(
            "late-added-recovery-rejected",
            ["old-late-recovery", "new-active"],
            {"error": "recovery_not_preauthorized", "code": 1020},
            trusted={OLD_DID: documents["old-trusted-no-recovery"]},
        ),
        resolve_case(
            "unsigned-provider-asserted",
            ["old-unsigned", "new-active"],
            {"status": "superseded", "currentDid": NEW_DID, "hops": ["provider_asserted"], "assurance": "provider_asserted"},
        ),
        {
            "id": "unsigned-hop-remains-unverified-before-chain-resolution",
            "operation": "verify_hop",
            "requestedDid": OLD_DID,
            "trustedDocuments": {OLD_DID: documents["old-trusted"]},
            "resolvedDocuments": {
                OLD_DID: documents["old-unsigned"],
                NEW_DID: documents["new-active"],
            },
            "cacheEdges": {},
            "expectedCacheEdges": {},
            "maxHops": 8,
            "expected": {
                "predecessorDid": OLD_DID,
                "successorDid": NEW_DID,
                "assurance": "unverified",
            },
        },
        resolve_case(
            "invalid-binding-proof-not-downgraded",
            ["old-bad-binding-proof", "new-active"],
            {"error": "invalid_proof", "code": 1020},
        ),
        resolve_case(
            "unsigned-provider-asserted-explicit-port",
            ["port-old-unsigned", "port-new-active"],
            {"status": "superseded", "currentDid": PORT_NEW_DID, "hops": ["provider_asserted"], "assurance": "provider_asserted"},
            trusted={PORT_OLD_DID: documents["port-old-trusted"]},
            requested_did=PORT_OLD_DID,
        ),
        provider_asserted_then_verified,
        resolve_case(
            "multi-hop-weakest-assurance",
            ["old-verified", "new-recovery", "newer-active"],
            {"status": "superseded", "currentDid": NEWER_DID, "hops": ["verified", "recovery_verified"], "assurance": "recovery_verified"},
            trusted={OLD_DID: documents["old-trusted"], NEW_DID: documents["new-active"]},
            expected_cache_edges={OLD_DID: NEW_DID, NEW_DID: NEWER_DID},
        ),
        resolve_case(
            "multi-hop-provider-asserted-is-weakest",
            ["old-unsigned", "new-recovery", "newer-active"],
            {"status": "superseded", "currentDid": NEWER_DID, "hops": ["provider_asserted", "recovery_verified"], "assurance": "provider_asserted"},
            trusted={OLD_DID: documents["old-trusted"], NEW_DID: documents["new-active"]},
            expected_cache_edges={NEW_DID: NEWER_DID},
        ),
        resolve_case(
            "stable-path-mismatch",
            ["old-wrong-path", "other-active"],
            {"error": "stable_path_mismatch", "code": 1020},
        ),
        resolve_case(
            "direct-successor-skipped",
            ["old-skip", "newer-active"],
            {"error": "direct_successor_required", "code": 1020},
        ),
        resolve_case(
            "cycle-rejected",
            ["old-verified", "new-cycle"],
            {"error": "cycle", "code": 1021},
        ),
        resolve_case(
            "fork-rejected",
            ["old-verified", "new-active"],
            {"error": "conflict", "code": 1021},
            cache_edges={OLD_DID: NEWER_DID},
            expected_cache_edges={OLD_DID: NEWER_DID},
        ),
        resolve_case(
            "hop-limit-rejected",
            ["old-verified", "new-recovery", "newer-active"],
            {"error": "max_hops_exceeded", "code": 1021},
            trusted={OLD_DID: documents["old-trusted"], NEW_DID: documents["new-active"]},
            max_hops=1,
        ),
        resolve_case(
            "tampered-409-hint-ignored",
            ["old-verified", "new-active"],
            {"status": "superseded", "currentDid": NEW_DID, "hops": ["verified"], "assurance": "verified"},
            current_hint=OTHER_DID,
            expected_cache_edges={OLD_DID: NEW_DID},
        ),
        *[
            {
                "id": case_id,
                "operation": "parse",
                "requestedDid": did,
                "trustedDocuments": {},
                "resolvedDocuments": {},
                "cacheEdges": {},
                "maxHops": 8,
                "expected": {"error": "unsupported_profile", "code": 1020},
            }
            for case_id, did in (
                ("bare-domain-not-automatic", "did:wba:example.com"),
                ("k1-not-automatic", "did:wba:example.com:users:alice:k1_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
                ("plain-legacy-not-automatic", "did:wba:example.com:users:alice"),
                ("other-did-method-not-automatic", "did:web:example.com:users:alice"),
            )
        ],
    ]

    vector_payload = {"schemaVersion": "1.1", "cases": cases}
    vector_path = OUTPUT / "transition_vectors.json"
    vector_path.write_text(json.dumps(vector_payload, indent=2, ensure_ascii=False) + "\n")
    vector_digest = hashlib.sha256(vector_path.read_bytes()).hexdigest()
    manifest = {
        "schemaVersion": "1.1",
        "suite": "anp-did-transition-v1",
        "generatedAt": CREATED,
        "vectorFile": "transition_vectors.json",
        "vectorSha256": vector_digest,
        "caseCount": len(cases),
        "privateKeyPolicy": "No private keys in fixtures; deterministic test-only seeds exist only in tools/generate_did_transition_vectors.py.",
    }
    (OUTPUT / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")


if __name__ == "__main__":
    main()
