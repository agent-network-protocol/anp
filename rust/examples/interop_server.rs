use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::path::PathBuf;

use anp::authentication::{DidWbaVerifier, DidWbaVerifierConfig};
use serde_json::{json, Value};
use tiny_http::{Header, Method, Response, Server, StatusCode};

fn main() {
    let args = std::env::args().skip(1).collect::<Vec<String>>();
    let did_json_path =
        PathBuf::from(read_option(&args, "--did-json").expect("--did-json is required"));
    let port: u16 = read_option(&args, "--port")
        .expect("--port is required")
        .parse()
        .expect("port must be a valid integer");
    let jwt_secret =
        read_option(&args, "--jwt-secret").unwrap_or_else(|| "test-secret".to_string());

    let did_document: Value = serde_json::from_str(
        &fs::read_to_string(&did_json_path).expect("did.json should be readable"),
    )
    .expect("did.json should be valid JSON");
    let mut verifier = DidWbaVerifier::new(DidWbaVerifierConfig {
        jwt_private_key: Some(jwt_secret.clone()),
        jwt_public_key: Some(jwt_secret),
        jwt_algorithm: "HS256".to_string(),
        ..DidWbaVerifierConfig::default()
    });

    let address = format!("127.0.0.1:{}", port);
    let server = Server::http(&address).expect("server should bind");
    println!("READY http://{}/auth", address);
    std::io::stdout().flush().expect("stdout should flush");

    let did_path = did_document_path(&did_document);

    for mut request in server.incoming_requests() {
        let request_url_path = request.url().to_string();
        if request_url_path == "/health" {
            let response = Response::from_string("ok").with_status_code(200);
            let _ = request.respond(response);
            continue;
        }
        if request_url_path == did_path {
            let response = build_json_response(200, &did_document, &BTreeMap::new());
            let _ = request.respond(response);
            continue;
        }

        let mut body = Vec::new();
        request
            .as_reader()
            .read_to_end(&mut body)
            .expect("request body should be readable");
        let headers = request_headers(&request);
        let host = headers
            .get("Host")
            .cloned()
            .unwrap_or_else(|| address.clone());
        let domain = host.split(':').next().unwrap_or(&host).to_string();
        let full_url = format!("http://{}{}", host, request.url());
        let runtime = tokio::runtime::Runtime::new().expect("runtime should start");
        let result = runtime.block_on(verifier.verify_request_with_did_document(
            method_to_str(request.method()),
            &full_url,
            &headers,
            if body.is_empty() {
                None
            } else {
                Some(body.as_slice())
            },
            Some(&domain),
            &did_document,
        ));

        match result {
            Ok(success) => {
                let response_body = json!({
                    "did": success.did,
                    "auth_scheme": success.auth_scheme,
                });
                let response = build_json_response(200, &response_body, &success.response_headers);
                let _ = request.respond(response);
            }
            Err(error) => {
                let response_body = json!({"detail": error.message});
                let response =
                    build_json_response(error.status_code, &response_body, &error.headers);
                let _ = request.respond(response);
            }
        }
    }
}

fn build_json_response(
    status_code: u16,
    payload: &Value,
    headers: &BTreeMap<String, String>,
) -> Response<std::io::Cursor<Vec<u8>>> {
    let body = serde_json::to_vec(payload).expect("response body should serialize");
    let mut response = Response::from_data(body).with_status_code(StatusCode(status_code));
    response.add_header(
        Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..])
            .expect("content type header should build"),
    );
    for (name, value) in headers {
        response.add_header(
            Header::from_bytes(name.as_bytes(), value.as_bytes())
                .expect("response header should build"),
        );
    }
    response
}

fn request_headers(request: &tiny_http::Request) -> BTreeMap<String, String> {
    request
        .headers()
        .iter()
        .map(|header| {
            (
                header.field.as_str().to_string(),
                header.value.as_str().to_string(),
            )
        })
        .collect()
}

fn method_to_str(method: &Method) -> &str {
    match method {
        Method::Get => "GET",
        Method::Post => "POST",
        Method::Put => "PUT",
        Method::Delete => "DELETE",
        Method::Patch => "PATCH",
        _ => "GET",
    }
}

fn did_document_path(did_document: &Value) -> String {
    let did = did_document
        .get("id")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let parts = did.split(':').collect::<Vec<&str>>();
    if parts.len() <= 3 {
        return "/.well-known/did.json".to_string();
    }
    format!("/{}/did.json", parts[3..].join("/"))
}

fn read_option(args: &[String], flag: &str) -> Option<String> {
    args.windows(2)
        .find(|window| window[0] == flag)
        .map(|window| window[1].clone())
}
