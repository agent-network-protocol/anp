use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use anp::authentication::{
    parse_did_wba_e1, resolve_current_did, verify_active_e1_document, DidDocumentFetcher,
    InMemoryTransitionCache,
};
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Manifest {
    vector_file: String,
    vector_sha256: String,
    case_count: usize,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct VectorSuite {
    cases: Vec<VectorCase>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct VectorCase {
    id: String,
    operation: String,
    requested_did: String,
    trusted_documents: HashMap<String, String>,
    resolved_documents: HashMap<String, String>,
    provider_documents: HashMap<String, String>,
    cache_edges: HashMap<String, String>,
    max_hops: usize,
    expected: Value,
}

fn fixture_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("rust directory has repository parent")
        .join("testdata/did_transition")
}

fn load_document(root: &Path, relative: &str) -> Value {
    serde_json::from_slice(&fs::read(root.join(relative)).expect("read fixture"))
        .expect("parse fixture")
}

#[test]
fn did_transition_shared_vectors() {
    let root = fixture_root();
    let manifest: Manifest =
        serde_json::from_slice(&fs::read(root.join("manifest.json")).expect("read manifest"))
            .expect("parse manifest");
    let vector_bytes = fs::read(root.join(&manifest.vector_file)).expect("read vectors");
    assert_eq!(
        format!("{:x}", Sha256::digest(&vector_bytes)),
        manifest.vector_sha256
    );
    let suite: VectorSuite = serde_json::from_slice(&vector_bytes).expect("parse vectors");
    assert_eq!(suite.cases.len(), manifest.case_count);

    for case in suite.cases {
        let resolved: HashMap<String, Value> = case
            .resolved_documents
            .iter()
            .map(|(did, path)| (did.clone(), load_document(&root, path)))
            .collect();
        let trusted: HashMap<String, Value> = case
            .trusted_documents
            .iter()
            .map(|(did, path)| (did.clone(), load_document(&root, path)))
            .collect();
        let providers: HashMap<String, Value> = case
            .provider_documents
            .iter()
            .map(|(did, path)| (did.clone(), load_document(&root, path)))
            .collect();
        let fetch = |did: &str| {
            resolved
                .get(did)
                .cloned()
                .ok_or_else(|| format!("missing resolved document {did}"))
        };
        let provider_fetch = |did: &str| {
            providers
                .get(did)
                .cloned()
                .ok_or_else(|| format!("missing provider document {did}"))
        };
        let outcome = match case.operation.as_str() {
            "parse" => parse_did_wba_e1(&case.requested_did).map(|_| Value::Null),
            "verify_active" => {
                let document = resolved.get(&case.requested_did).expect("active fixture");
                verify_active_e1_document(&case.requested_did, document).map(|_| {
                    serde_json::json!({
                        "status": "active",
                        "currentDid": case.requested_did,
                        "hops": [],
                        "assurance": null
                    })
                })
            }
            "resolve" => {
                let mut cache = InMemoryTransitionCache::new(case.cache_edges);
                resolve_current_did(
                    &case.requested_did,
                    &fetch,
                    &trusted,
                    Some(&provider_fetch as &dyn DidDocumentFetcher),
                    &mut cache,
                    case.max_hops,
                )
                .map(|result| {
                    serde_json::json!({
                        "status": result.status,
                        "currentDid": result.current_did,
                        "hops": result.hops.into_iter().map(|hop| hop.assurance).collect::<Vec<_>>(),
                        "assurance": result.assurance
                    })
                })
            }
            other => panic!("unknown operation {other}"),
        };
        match outcome {
            Ok(actual) => assert_eq!(actual, case.expected, "case {}", case.id),
            Err(error) => assert_eq!(
                serde_json::json!({"error": error.kind, "code": error.code}),
                case.expected,
                "case {}: {error}",
                case.id
            ),
        }
    }
}
