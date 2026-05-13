#![allow(dead_code)]

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use std::sync::OnceLock;

use serde_json::Value;
use tiny_http::{Header, Response, Server};

const RUST_INTEROP_CONFIG_JSON: &str = include_str!("../../../tests/rust_interop_config.json");
static RELEASED_PYTHON_ANP_VERSION: OnceLock<String> = OnceLock::new();

pub fn released_python_anp_version() -> &'static str {
    RELEASED_PYTHON_ANP_VERSION
        .get_or_init(|| {
            let value: Value = serde_json::from_str(RUST_INTEROP_CONFIG_JSON)
                .expect("rust interop config must be valid JSON");
            value
                .get("released_python_anp_version")
                .and_then(Value::as_str)
                .expect("released_python_anp_version must be configured")
                .to_string()
        })
        .as_str()
}

pub struct TestTempDir {
    path: PathBuf,
}

impl TestTempDir {
    pub fn new(prefix: &str) -> std::io::Result<Self> {
        let mut attempts = 0_u32;
        loop {
            let path = std::env::temp_dir().join(format!(
                "{}-{}-{}",
                prefix,
                std::process::id(),
                unique_suffix()
            ));
            match std::fs::create_dir(&path) {
                Ok(()) => return Ok(Self { path }),
                Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists && attempts < 100 => {
                    attempts += 1;
                }
                Err(err) => return Err(err),
            }
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TestTempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

pub struct TestNamedTempFile {
    path: PathBuf,
}

impl TestNamedTempFile {
    pub fn new(prefix: &str) -> std::io::Result<Self> {
        let dir = std::env::temp_dir();
        let mut attempts = 0_u32;
        loop {
            let path = dir.join(format!(
                "{}-{}-{}.json",
                prefix,
                std::process::id(),
                unique_suffix()
            ));
            match std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)
            {
                Ok(_) => return Ok(Self { path }),
                Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists && attempts < 100 => {
                    attempts += 1;
                }
                Err(err) => return Err(err),
            }
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TestNamedTempFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

pub fn tempdir(prefix: &str) -> std::io::Result<TestTempDir> {
    TestTempDir::new(prefix)
}

pub fn named_temp_file(prefix: &str) -> std::io::Result<TestNamedTempFile> {
    TestNamedTempFile::new(prefix)
}

pub struct JsonTestServer {
    uri: String,
}

impl JsonTestServer {
    pub fn start(routes: impl IntoIterator<Item = (&'static str, Value)>) -> Self {
        let server = Server::http("127.0.0.1:0").expect("test HTTP server should bind");
        let uri = format!("http://{}", server.server_addr());
        let routes: HashMap<String, String> = routes
            .into_iter()
            .map(|(path, body)| {
                (
                    path.to_string(),
                    serde_json::to_string(&body).expect("test JSON body should serialize"),
                )
            })
            .collect();

        thread::spawn(move || loop {
            match server.recv_timeout(Duration::from_millis(100)) {
                Ok(Some(request)) => {
                    let body = routes.get(request.url()).cloned();
                    let response = match body {
                        Some(body) if request.method().as_str() == "GET" => {
                            Response::from_string(body).with_header(
                                Header::from_bytes("Content-Type", "application/json")
                                    .expect("valid header"),
                            )
                        }
                        _ => Response::from_string("not found").with_status_code(404),
                    };
                    let _ = request.respond(response);
                }
                Ok(None) => continue,
                Err(_) => break,
            }
        });

        Self { uri }
    }

    pub fn uri(&self) -> String {
        self.uri.clone()
    }
}

pub struct RecordingJsonTestServer {
    uri: String,
    requests: Arc<Mutex<Vec<RecordedRequest>>>,
}

#[derive(Clone, Debug, Default)]
pub struct RecordedRequest {
    pub path: String,
    pub headers: BTreeMap<String, String>,
}

impl RecordingJsonTestServer {
    pub fn start(routes: impl IntoIterator<Item = (&'static str, Value)>) -> Self {
        let server = Server::http("127.0.0.1:0").expect("test HTTP server should bind");
        let uri = format!("http://{}", server.server_addr());
        let routes: HashMap<String, String> = routes
            .into_iter()
            .map(|(path, body)| {
                (
                    path.to_string(),
                    serde_json::to_string(&body).expect("test JSON body should serialize"),
                )
            })
            .collect();
        let requests = Arc::new(Mutex::new(Vec::<RecordedRequest>::new()));
        let captured = Arc::clone(&requests);

        thread::spawn(move || loop {
            match server.recv_timeout(Duration::from_millis(100)) {
                Ok(Some(request)) => {
                    let path = request.url().to_string();
                    let headers = request
                        .headers()
                        .iter()
                        .map(|header| {
                            (
                                header.field.as_str().to_string(),
                                header.value.as_str().to_string(),
                            )
                        })
                        .collect::<BTreeMap<_, _>>();
                    captured
                        .lock()
                        .expect("request capture should not be poisoned")
                        .push(RecordedRequest {
                            path: path.clone(),
                            headers,
                        });
                    let body = routes.get(&path).cloned();
                    let response = match body {
                        Some(body) if request.method().as_str() == "GET" => {
                            Response::from_string(body).with_header(
                                Header::from_bytes("Content-Type", "application/json")
                                    .expect("valid header"),
                            )
                        }
                        _ => Response::from_string("not found").with_status_code(404),
                    };
                    let _ = request.respond(response);
                }
                Ok(None) => continue,
                Err(_) => break,
            }
        });

        Self { uri, requests }
    }

    pub fn uri(&self) -> String {
        self.uri.clone()
    }

    pub fn requests(&self) -> Vec<RecordedRequest> {
        self.requests
            .lock()
            .expect("request capture should not be poisoned")
            .clone()
    }
}

fn unique_suffix() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};

    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let counter = COUNTER.fetch_add(1, Ordering::Relaxed);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();
    format!("{}-{}", nanos, counter)
}
