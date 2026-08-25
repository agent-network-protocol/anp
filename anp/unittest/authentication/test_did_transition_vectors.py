import hashlib
import json
from pathlib import Path

import pytest

from anp.authentication import (
    DidTransitionError,
    InMemoryTransitionCache,
    parse_did_wba_e1,
    resolve_current_did,
    verify_active_e1_document,
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
    providers = {did: load_json(path) for did, path in case["providerDocuments"].items()}

    def fetcher(did):
        return resolved[did]

    def provider_fetcher(did):
        return providers[did]

    expected = case["expected"]
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
        else:
            transition = resolve_current_did(
                case["requestedDid"],
                fetcher,
                trusted_documents=trusted,
                provider_fetcher=provider_fetcher,
                cache=InMemoryTransitionCache(case["cacheEdges"]),
                max_hops=case["maxHops"],
            )
            result = {
                "status": transition.status.value,
                "currentDid": transition.current_did,
                "hops": [hop.assurance.value for hop in transition.hops],
                "assurance": transition.assurance.value if transition.assurance else None,
            }
    except DidTransitionError as exc:
        assert expected == {"error": exc.kind.value, "code": exc.code}
    else:
        assert result == expected
