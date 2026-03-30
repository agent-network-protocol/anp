use std::fs;
use std::path::PathBuf;

use anp::authentication::{create_did_wba_document, DidDocumentOptions, DidProfile};

fn main() {
    let mut profile = DidProfile::E1;
    let mut hostname = "demo.agent-network".to_string();

    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--profile" => {
                if let Some(value) = args.next() {
                    profile = DidProfile::from_str(&value).expect("profile must be one of: e1, k1, plain_legacy");
                }
            }
            "--hostname" => {
                hostname = args.next().expect("hostname value is required");
            }
            _ => {}
        }
    }

    let bundle = create_did_wba_document(
        &hostname,
        DidDocumentOptions::default()
            .with_profile(profile)
            .with_path_segments(["agents", "demo"])
            .with_agent_description_url(format!("https://{hostname}/agents/demo")),
    )
    .expect("DID creation should succeed");

    let output_dir = PathBuf::from("examples/generated").join(profile.as_str());
    fs::create_dir_all(&output_dir).expect("output directory should be created");

    let did_path = output_dir.join("did.json");
    fs::write(
        &did_path,
        serde_json::to_vec_pretty(&bundle.did_document).expect("DID document should serialize"),
    )
    .expect("DID document should be written");
    println!("DID document saved to {}", did_path.display());

    for (fragment, key_pair) in &bundle.keys {
        let private_path = output_dir.join(format!("{}_private.pem", fragment));
        let public_path = output_dir.join(format!("{}_public.pem", fragment));
        fs::write(&private_path, &key_pair.private_key_pem).expect("private key should be written");
        fs::write(&public_path, &key_pair.public_key_pem).expect("public key should be written");
        println!(
            "Registered verification method {} -> private key: {} public key: {}",
            fragment,
            private_path.file_name().unwrap().to_string_lossy(),
            public_path.file_name().unwrap().to_string_lossy(),
        );
    }

    println!("Generated DID identifier: {}", bundle.did().unwrap_or("<unknown>"));
    if let Some(proof) = bundle.did_document.get("proof") {
        println!(
            "Generated proof profile: {} {}",
            proof.get("type").and_then(serde_json::Value::as_str).unwrap_or("<unknown>"),
            proof
                .get("cryptosuite")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("<legacy>"),
        );
    }
}
