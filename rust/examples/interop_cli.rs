use std::collections::BTreeMap;

use anp::authentication::{
    create_did_wba_document, generate_auth_header, generate_http_signature_headers,
    DidDocumentOptions, DidProfile,
};
use serde_json::json;

fn main() {
    let args = std::env::args().skip(1).collect::<Vec<String>>();
    if args.is_empty() {
        eprintln!("Usage: cargo run --example interop_cli -- <did-fixture|auth-fixture> [options]");
        std::process::exit(1);
    }

    match args[0].as_str() {
        "did-fixture" => run_did_fixture(&args[1..]),
        "auth-fixture" => run_auth_fixture(&args[1..]),
        other => {
            eprintln!("Unsupported subcommand: {}", other);
            std::process::exit(1);
        }
    }
}

fn run_did_fixture(args: &[String]) {
    let profile = read_option(args, "--profile").unwrap_or_else(|| "e1".to_string());
    let hostname = read_option(args, "--hostname").unwrap_or_else(|| "example.com".to_string());
    let bundle = create_bundle(&hostname, &profile);
    println!(
        "{}",
        serde_json::to_string(&json!({
            "profile": profile,
            "did_document": bundle.did_document,
            "keys": bundle.keys,
        }))
        .expect("fixture should serialize")
    );
}

fn run_auth_fixture(args: &[String]) {
    let profile = read_option(args, "--profile").unwrap_or_else(|| "e1".to_string());
    let hostname = read_option(args, "--hostname").unwrap_or_else(|| "example.com".to_string());
    let scheme = read_option(args, "--scheme").unwrap_or_else(|| "http".to_string());
    let service_domain = read_option(args, "--service-domain")
        .unwrap_or_else(|| "api.example.com".to_string());
    let request_url = read_option(args, "--url")
        .unwrap_or_else(|| format!("https://{}/orders", service_domain));
    let request_method = read_option(args, "--method").unwrap_or_else(|| "GET".to_string());
    let body = read_option(args, "--body").unwrap_or_default();

    let bundle = create_bundle(&hostname, &profile);
    let private_key = bundle
        .load_private_key("key-1")
        .expect("private key should load");

    let output = match scheme.as_str() {
        "legacy" => {
            let header = generate_auth_header(
                &bundle.did_document,
                &service_domain,
                &private_key,
                "1.1",
            )
            .expect("legacy auth header should generate");
            json!({
                "profile": profile,
                "scheme": scheme,
                "service_domain": service_domain,
                "did_document": bundle.did_document,
                "keys": bundle.keys,
                "headers": {"Authorization": header},
            })
        }
        "http" => {
            let body_bytes = if body.is_empty() { None } else { Some(body.as_bytes()) };
            let headers = generate_http_signature_headers(
                &bundle.did_document,
                &request_url,
                &request_method,
                &private_key,
                Some(&BTreeMap::new()),
                body_bytes,
                Default::default(),
            )
            .expect("HTTP signature headers should generate");
            json!({
                "profile": profile,
                "scheme": scheme,
                "service_domain": service_domain,
                "request_url": request_url,
                "request_method": request_method,
                "body": body,
                "did_document": bundle.did_document,
                "keys": bundle.keys,
                "headers": headers,
            })
        }
        other => panic!("Unsupported scheme: {}", other),
    };

    println!("{}", serde_json::to_string(&output).expect("fixture should serialize"));
}

fn create_bundle(hostname: &str, profile: &str) -> anp::authentication::DidDocumentBundle {
    let did_profile = DidProfile::from_str(profile).expect("profile must be one of: e1, k1, plain_legacy");
    create_did_wba_document(
        hostname,
        DidDocumentOptions::default()
            .with_profile(did_profile)
            .with_path_segments(["user", "interop"]),
    )
    .expect("DID fixture should be created")
}

fn read_option(args: &[String], flag: &str) -> Option<String> {
    args.windows(2)
        .find(|window| window[0] == flag)
        .map(|window| window[1].clone())
}
