import hashlib
import json
from pathlib import Path

import pytest

from anp.authentication import (
    DidTransitionError,
    InMemoryTransitionCache,
    TransitionErrorKind,
    parse_did_wba_e1,
    resolve_current_did,
    verify_active_e1_document,
    verify_transition_hop,
)


ROOT = Path(__file__).resolve().parents[3]
FIXTURE_ROOT = ROOT / "testdata" / "did_transition"


def load_json(relative_path: str) -> dict:
    return json.loads((FIXTURE_ROOT / relative_path).read_text())


MANIFEST = load_json("manifest.json")
VECTORS = load_json(MANIFEST["vectorFile"])


def test_transition_vector_manifest_is_complete_and_immutable():
    vector_bytes = (FIXTURE_ROOT / MANIFEST["vectorFile"]).read_bytes()
    assert hashlib.sha256(vector_bytes).hexdigest() == MANIFEST["vectorSha256"]
    assert MANIFEST["caseCount"] == len(VECTORS["cases"])
    assert len({case["id"] for case in VECTORS["cases"]}) == len(VECTORS["cases"])


@pytest.mark.parametrize("case", VECTORS["cases"], ids=lambda case: case["id"])
def test_did_transition_vector(case):
    resolved = {did: load_json(path) for did, path in case["resolvedDocuments"].items()}
    trusted = {did: load_json(path) for did, path in case["trustedDocuments"].items()}

    def fetcher(did):
        return resolved[did]

    expected = case["expected"]
    cache = InMemoryTransitionCache(case["cacheEdges"])
    try:
        if case["operation"] == "parse":
            parse_did_wba_e1(case["requestedDid"])
            result = None
        elif case["operation"] == "verify_active":
            verify_active_e1_document(case["requestedDid"], resolved[case["requestedDid"]])
            result = {
                "status": "active",
                "currentDid": case["requestedDid"],
                "hops": [],
                "assurance": None,
            }
        elif case["operation"] == "verify_hop":
            predecessor = resolved[case["requestedDid"]]
            successor = resolved[predecessor["successorDid"]]
            hop = verify_transition_hop(
                predecessor,
                successor,
                trusted_predecessor=trusted.get(case["requestedDid"]),
            )
            result = {
                "predecessorDid": hop.predecessor_did,
                "successorDid": hop.successor_did,
                "assurance": hop.assurance.value,
            }
        elif case["operation"] in {
            "resolve",
            "resolve_ignoring_hint",
            "resolve_after_provider_asserted",
        }:
            if case["operation"] == "resolve_ignoring_hint":
                assert case["untrustedCurrentDidHint"]
            if case["operation"] == "resolve_after_provider_asserted":
                prelude = {
                    did: load_json(path)
                    for did, path in case["preludeResolvedDocuments"].items()
                }
                prelude_result = resolve_current_did(
                    case["requestedDid"],
                    lambda did: prelude[did],
                    trusted_documents=trusted,
                    cache=cache,
                    max_hops=case["maxHops"],
                )
                assert prelude_result.assurance.value == "provider_asserted"
                assert cache.snapshot() == case["cacheEdges"]
            transition = resolve_current_did(
                case["requestedDid"],
                fetcher,
                trusted_documents=trusted,
                cache=cache,
                max_hops=case["maxHops"],
            )
            result = {
                "status": transition.status.value,
                "currentDid": transition.current_did,
                "hops": [hop.assurance.value for hop in transition.hops],
                "assurance": transition.assurance.value if transition.assurance else None,
            }
        else:
            raise AssertionError(f"unknown operation {case['operation']}")
    except DidTransitionError as exc:
        assert expected == {"error": exc.kind.value, "code": exc.code}
    else:
        assert result == expected
    if case["operation"].startswith("resolve"):
        assert cache.snapshot() == case["expectedCacheEdges"]


def test_successor_fetch_preserves_transition_error_kind():
    predecessor = load_json("documents/old-verified.json")

    def fetcher(did):
        if did == predecessor["id"]:
            return predecessor
        raise DidTransitionError(TransitionErrorKind.INVALID_DOCUMENT, "typed fetch failure")

    with pytest.raises(DidTransitionError) as exc_info:
        resolve_current_did(predecessor["id"], fetcher)

    assert exc_info.value.kind is TransitionErrorKind.INVALID_DOCUMENT
