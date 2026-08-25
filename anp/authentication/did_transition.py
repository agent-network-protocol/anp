"""Verification and forward resolution for did:wba E1 transitions."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, Mapping, Optional, Protocol

from cryptography.hazmat.primitives.asymmetric import ed25519

from anp.proof import verify_w3c_proof

from .did_wba import (
    _extract_public_key,
    _find_verification_method,
    _is_assertion_method_authorized_in_document,
    compute_multikey_fingerprint,
)


ANP_DID_SUPERSEDED = 1019
ANP_DID_TRANSITION_INVALID = 1020
ANP_DID_TRANSITION_CONFLICT = 1021
DEFAULT_MAX_TRANSITION_HOPS = 8

_E1_SEGMENT = re.compile(r"^e1_[A-Za-z0-9_-]{43}$")
_CANONICAL_UTC = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
_PROVIDER_FIELDS = {
    "type",
    "providerDid",
    "predecessorDid",
    "successorDid",
    "stableSubjectPath",
    "issuedAt",
    "proof",
}


class TransitionAssurance(str, Enum):
    VERIFIED = "verified"
    RECOVERY_VERIFIED = "recovery_verified"
    PROVIDER_ASSERTED = "provider_asserted"
    UNVERIFIED = "unverified"


class TransitionStatus(str, Enum):
    ACTIVE = "active"
    SUPERSEDED = "superseded"


class TransitionErrorKind(str, Enum):
    UNSUPPORTED_PROFILE = "unsupported_profile"
    INVALID_DOCUMENT = "invalid_document"
    INVALID_PROOF = "invalid_proof"
    RECOVERY_NOT_PREAUTHORIZED = "recovery_not_preauthorized"
    INVALID_PROVIDER_ASSERTION = "invalid_provider_assertion"
    STABLE_PATH_MISMATCH = "stable_path_mismatch"
    DIRECT_SUCCESSOR_REQUIRED = "direct_successor_required"
    CYCLE = "cycle"
    CONFLICT = "conflict"
    MAX_HOPS_EXCEEDED = "max_hops_exceeded"
    NETWORK_ERROR = "network_error"


_CONFLICT_ERRORS = {
    TransitionErrorKind.CYCLE,
    TransitionErrorKind.CONFLICT,
    TransitionErrorKind.MAX_HOPS_EXCEEDED,
}


class DidTransitionError(ValueError):
    def __init__(self, kind: TransitionErrorKind, message: str):
        self.kind = kind
        self.code = (
            ANP_DID_TRANSITION_CONFLICT
            if kind in _CONFLICT_ERRORS
            else ANP_DID_TRANSITION_INVALID
        )
        super().__init__(message)


@dataclass(frozen=True)
class DidWbaE1Profile:
    did: str
    origin: str
    stable_subject_path: str
    fingerprint: str


@dataclass(frozen=True)
class TransitionHop:
    predecessor_did: str
    successor_did: str
    assurance: TransitionAssurance


@dataclass(frozen=True)
class TransitionResult:
    requested_did: str
    current_did: str
    status: TransitionStatus
    assurance: Optional[TransitionAssurance]
    hops: tuple[TransitionHop, ...] = field(default_factory=tuple)


class TransitionCache(Protocol):
    def get_successor(self, predecessor_did: str) -> Optional[str]: ...

    def compare_and_set(self, predecessor_did: str, successor_did: str) -> bool: ...


class InMemoryTransitionCache:
    """Small CAS cache suitable for callers that do not have a persistent store."""

    def __init__(self, edges: Optional[Mapping[str, str]] = None):
        self._edges = dict(edges or {})

    def get_successor(self, predecessor_did: str) -> Optional[str]:
        return self._edges.get(predecessor_did)

    def compare_and_set(self, predecessor_did: str, successor_did: str) -> bool:
        existing = self._edges.get(predecessor_did)
        if existing is not None:
            return existing == successor_did
        self._edges[predecessor_did] = successor_did
        return True

    def snapshot(self) -> Dict[str, str]:
        return dict(self._edges)


DocumentFetcher = Callable[[str], Dict[str, Any]]


def parse_did_wba_e1(did: str) -> DidWbaE1Profile:
    parts = did.split(":")
    if len(parts) < 5 or parts[0:2] != ["did", "wba"]:
        raise DidTransitionError(
            TransitionErrorKind.UNSUPPORTED_PROFILE,
            "automatic transition requires a path-based did:wba E1 DID",
        )
    segment = parts[-1]
    if not _E1_SEGMENT.fullmatch(segment):
        raise DidTransitionError(
            TransitionErrorKind.UNSUPPORTED_PROFILE,
            "automatic transition supports only the e1 profile",
        )
    return DidWbaE1Profile(
        did=did,
        origin=parts[2],
        stable_subject_path=":".join(parts[2:-1]),
        fingerprint=segment[3:],
    )


def _binding_method(document: Dict[str, Any], profile: DidWbaE1Profile) -> Optional[dict]:
    for method in document.get("verificationMethod", []):
        if not isinstance(method, dict):
            continue
        try:
            public_key = _extract_public_key(method)
        except ValueError:
            continue
        if isinstance(public_key, ed25519.Ed25519PublicKey):
            if compute_multikey_fingerprint(public_key) == profile.fingerprint:
                return method
    return None


def _require_document_id(did: str, document: Dict[str, Any]) -> None:
    if document.get("id") != did:
        raise DidTransitionError(
            TransitionErrorKind.INVALID_DOCUMENT,
            f"DID Document id does not match {did}",
        )


def verify_active_e1_document(did: str, document: Dict[str, Any]) -> None:
    profile = parse_did_wba_e1(did)
    _require_document_id(did, document)
    if document.get("deactivated") is True:
        raise DidTransitionError(
            TransitionErrorKind.INVALID_DOCUMENT,
            "expected an active DID Document",
        )
    proof = document.get("proof")
    if not isinstance(proof, dict):
        raise DidTransitionError(TransitionErrorKind.INVALID_PROOF, "active E1 proof is required")
    verification_method_id = proof.get("verificationMethod")
    if not isinstance(verification_method_id, str):
        raise DidTransitionError(TransitionErrorKind.INVALID_PROOF, "proof verificationMethod is required")
    method = _find_verification_method(document, verification_method_id)
    if not method or not _is_assertion_method_authorized_in_document(
        document, verification_method_id
    ):
        raise DidTransitionError(TransitionErrorKind.INVALID_PROOF, "binding key is not authorized")
    try:
        public_key = _extract_public_key(method)
    except ValueError as exc:
        raise DidTransitionError(TransitionErrorKind.INVALID_PROOF, "invalid binding key") from exc
    if not isinstance(public_key, ed25519.Ed25519PublicKey):
        raise DidTransitionError(TransitionErrorKind.INVALID_PROOF, "binding key must be Ed25519")
    if compute_multikey_fingerprint(public_key) != profile.fingerprint:
        raise DidTransitionError(TransitionErrorKind.INVALID_PROOF, "binding fingerprint mismatch")
    if not verify_w3c_proof(document, public_key, expected_purpose="assertionMethod"):
        raise DidTransitionError(TransitionErrorKind.INVALID_PROOF, "active E1 proof verification failed")


def _provider_did(profile: DidWbaE1Profile) -> str:
    return f"did:wba:{profile.origin}"


def _verify_provider_assertion(
    predecessor_document: Dict[str, Any],
    predecessor: DidWbaE1Profile,
    successor: DidWbaE1Profile,
    provider_fetcher: Optional[DocumentFetcher],
) -> None:
    assertion = predecessor_document.get("providerTransitionAssertion")
    if not isinstance(assertion, dict) or set(assertion) != _PROVIDER_FIELDS:
        raise DidTransitionError(
            TransitionErrorKind.INVALID_PROVIDER_ASSERTION,
            "providerTransitionAssertion has an invalid shape",
        )
    provider_did = _provider_did(predecessor)
    issued_at = assertion.get("issuedAt")
    proof = assertion.get("proof")
    if (
        assertion.get("type") != "DidWbaProviderTransitionAssertion"
        or assertion.get("providerDid") != provider_did
        or assertion.get("predecessorDid") != predecessor.did
        or assertion.get("successorDid") != successor.did
        or assertion.get("stableSubjectPath") != predecessor.stable_subject_path
        or not isinstance(issued_at, str)
        or not _CANONICAL_UTC.fullmatch(issued_at)
        or not isinstance(proof, dict)
        or proof.get("created") != issued_at
    ):
        raise DidTransitionError(
            TransitionErrorKind.INVALID_PROVIDER_ASSERTION,
            "providerTransitionAssertion binding fields are invalid",
        )
    if provider_fetcher is None:
        raise DidTransitionError(
            TransitionErrorKind.INVALID_PROVIDER_ASSERTION,
            "provider DID resolver is required",
        )
    try:
        provider_document = provider_fetcher(provider_did)
    except Exception as exc:
        raise DidTransitionError(TransitionErrorKind.NETWORK_ERROR, str(exc)) from exc
    _require_document_id(provider_did, provider_document)
    method_id = proof.get("verificationMethod")
    if not isinstance(method_id, str) or not method_id.startswith(f"{provider_did}#"):
        raise DidTransitionError(
            TransitionErrorKind.INVALID_PROVIDER_ASSERTION,
            "provider proof key is outside providerDid",
        )
    method = _find_verification_method(provider_document, method_id)
    if not method or not _is_assertion_method_authorized_in_document(provider_document, method_id):
        raise DidTransitionError(
            TransitionErrorKind.INVALID_PROVIDER_ASSERTION,
            "provider proof key is not authorized",
        )
    try:
        public_key = _extract_public_key(method)
    except ValueError as exc:
        raise DidTransitionError(
            TransitionErrorKind.INVALID_PROVIDER_ASSERTION, "invalid provider proof key"
        ) from exc
    if not verify_w3c_proof(assertion, public_key, expected_purpose="assertionMethod"):
        raise DidTransitionError(
            TransitionErrorKind.INVALID_PROVIDER_ASSERTION,
            "providerTransitionAssertion proof verification failed",
        )


def verify_transition_hop(
    predecessor_document: Dict[str, Any],
    successor_document: Dict[str, Any],
    *,
    trusted_predecessor: Optional[Dict[str, Any]] = None,
    provider_fetcher: Optional[DocumentFetcher] = None,
) -> TransitionHop:
    predecessor_did = predecessor_document.get("id")
    successor_did = predecessor_document.get("successorDid")
    if not isinstance(predecessor_did, str) or not isinstance(successor_did, str):
        raise DidTransitionError(
            TransitionErrorKind.INVALID_DOCUMENT,
            "deactivated predecessor requires id and successorDid",
        )
    predecessor = parse_did_wba_e1(predecessor_did)
    successor = parse_did_wba_e1(successor_did)
    _require_document_id(successor_did, successor_document)
    if predecessor_document.get("deactivated") is not True:
        raise DidTransitionError(TransitionErrorKind.INVALID_DOCUMENT, "predecessor is not deactivated")
    if predecessor.stable_subject_path != successor.stable_subject_path:
        raise DidTransitionError(
            TransitionErrorKind.STABLE_PATH_MISMATCH,
            "predecessor and successor stable subject paths differ",
        )
    if _binding_method(predecessor_document, predecessor) is None:
        raise DidTransitionError(
            TransitionErrorKind.INVALID_DOCUMENT,
            "deactivated predecessor does not retain its binding key",
        )
    aliases = successor_document.get("alsoKnownAs")
    if isinstance(aliases, list):
        same_subject_predecessors = []
        for alias in aliases:
            if not isinstance(alias, str):
                continue
            try:
                alias_profile = parse_did_wba_e1(alias)
            except DidTransitionError:
                continue
            if alias_profile.stable_subject_path == successor.stable_subject_path:
                same_subject_predecessors.append(alias)
        if same_subject_predecessors and predecessor_did not in same_subject_predecessors:
            raise DidTransitionError(
                TransitionErrorKind.DIRECT_SUCCESSOR_REQUIRED,
                "successor identifies a different direct predecessor",
            )

    provider_present = "providerTransitionAssertion" in predecessor_document
    if provider_present:
        _verify_provider_assertion(
            predecessor_document, predecessor, successor, provider_fetcher
        )

    proof = predecessor_document.get("proof")
    assurance = TransitionAssurance.UNVERIFIED
    if proof is not None:
        if not isinstance(proof, dict):
            raise DidTransitionError(TransitionErrorKind.INVALID_PROOF, "transition proof is invalid")
        method_id = proof.get("verificationMethod")
        if not isinstance(method_id, str):
            raise DidTransitionError(TransitionErrorKind.INVALID_PROOF, "transition proof key is missing")
        binding = _binding_method(predecessor_document, predecessor)
        if binding and binding.get("id") == method_id:
            public_key = _extract_public_key(binding)
            if not verify_w3c_proof(
                predecessor_document, public_key, expected_purpose="assertionMethod"
            ):
                raise DidTransitionError(TransitionErrorKind.INVALID_PROOF, "old binding proof failed")
            assurance = TransitionAssurance.VERIFIED
        else:
            trusted_method = (
                _find_verification_method(trusted_predecessor, method_id)
                if trusted_predecessor
                else None
            )
            if not trusted_predecessor or not trusted_method or not _is_assertion_method_authorized_in_document(
                trusted_predecessor, method_id
            ):
                raise DidTransitionError(
                    TransitionErrorKind.RECOVERY_NOT_PREAUTHORIZED,
                    "recovery key was not pre-authorized by the trusted predecessor",
                )
            try:
                public_key = _extract_public_key(trusted_method)
            except ValueError as exc:
                raise DidTransitionError(TransitionErrorKind.INVALID_PROOF, "invalid recovery key") from exc
            if not verify_w3c_proof(
                predecessor_document, public_key, expected_purpose="assertionMethod"
            ):
                raise DidTransitionError(TransitionErrorKind.INVALID_PROOF, "recovery proof failed")
            assurance = TransitionAssurance.RECOVERY_VERIFIED
    elif provider_present:
        assurance = TransitionAssurance.PROVIDER_ASSERTED

    return TransitionHop(predecessor_did, successor_did, assurance)


_ASSURANCE_RANK = {
    TransitionAssurance.VERIFIED: 0,
    TransitionAssurance.RECOVERY_VERIFIED: 1,
    TransitionAssurance.PROVIDER_ASSERTED: 2,
    TransitionAssurance.UNVERIFIED: 3,
}


def resolve_current_did(
    requested_did: str,
    fetcher: DocumentFetcher,
    *,
    trusted_predecessor: Optional[Dict[str, Any]] = None,
    trusted_documents: Optional[Mapping[str, Dict[str, Any]]] = None,
    provider_fetcher: Optional[DocumentFetcher] = None,
    cache: Optional[TransitionCache] = None,
    max_hops: int = DEFAULT_MAX_TRANSITION_HOPS,
) -> TransitionResult:
    parse_did_wba_e1(requested_did)
    if max_hops < 1:
        raise DidTransitionError(TransitionErrorKind.MAX_HOPS_EXCEEDED, "max_hops must be positive")
    if cache is None:
        cache = InMemoryTransitionCache()
    trusted = dict(trusted_documents or {})
    if trusted_predecessor is not None:
        trusted[requested_did] = trusted_predecessor
    current = requested_did
    visited: set[str] = set()
    hops: list[TransitionHop] = []
    verified_edges: list[tuple[str, str]] = []

    while True:
        if current in visited:
            raise DidTransitionError(TransitionErrorKind.CYCLE, "transition chain contains a cycle")
        visited.add(current)
        try:
            document = fetcher(current)
        except DidTransitionError:
            raise
        except Exception as exc:
            raise DidTransitionError(TransitionErrorKind.NETWORK_ERROR, str(exc)) from exc
        _require_document_id(current, document)
        if document.get("deactivated") is not True:
            verify_active_e1_document(current, document)
            for predecessor_did, successor_did in verified_edges:
                if not cache.compare_and_set(predecessor_did, successor_did):
                    raise DidTransitionError(
                        TransitionErrorKind.CONFLICT,
                        "a different successor is already cached for predecessor",
                    )
            assurance = (
                max((hop.assurance for hop in hops), key=_ASSURANCE_RANK.get)
                if hops
                else None
            )
            return TransitionResult(
                requested_did=requested_did,
                current_did=current,
                status=TransitionStatus.SUPERSEDED if hops else TransitionStatus.ACTIVE,
                assurance=assurance,
                hops=tuple(hops),
            )
        if len(hops) >= max_hops:
            raise DidTransitionError(
                TransitionErrorKind.MAX_HOPS_EXCEEDED,
                "transition chain exceeds max_hops",
            )
        successor_did = document.get("successorDid")
        if not isinstance(successor_did, str):
            raise DidTransitionError(
                TransitionErrorKind.INVALID_DOCUMENT,
                "deactivated transition document has no successorDid",
            )
        if successor_did in visited:
            raise DidTransitionError(TransitionErrorKind.CYCLE, "transition chain contains a cycle")
        try:
            successor_document = fetcher(successor_did)
        except DidTransitionError:
            raise
        except Exception as exc:
            raise DidTransitionError(TransitionErrorKind.NETWORK_ERROR, str(exc)) from exc
        hop = verify_transition_hop(
            document,
            successor_document,
            trusted_predecessor=trusted.get(current),
            provider_fetcher=provider_fetcher,
        )
        cached_successor = cache.get_successor(current)
        if cached_successor is not None and cached_successor != successor_did:
            raise DidTransitionError(
                TransitionErrorKind.CONFLICT,
                "a different successor is already cached for predecessor",
            )
        if hop.assurance in {
            TransitionAssurance.VERIFIED,
            TransitionAssurance.RECOVERY_VERIFIED,
        }:
            verified_edges.append((current, successor_did))
        hops.append(hop)
        current = successor_did
