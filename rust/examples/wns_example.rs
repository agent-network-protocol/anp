use anp::wns::{
    build_handle_service_entry, build_resolution_url, build_wba_uri, parse_wba_uri, validate_handle,
};

fn main() {
    let handle = "Alice.Example.COM";
    let (local_part, domain) = validate_handle(handle).expect("handle should validate");
    println!("normalized handle: {}.{}", local_part, domain);
    println!(
        "resolution url: {}",
        build_resolution_url(&local_part, &domain)
    );

    let uri = build_wba_uri(&local_part, &domain);
    let parsed = parse_wba_uri(&uri).expect("URI should parse");
    println!("parsed URI handle: {}", parsed.handle);

    let handle_service =
        build_handle_service_entry("did:wba:example.com:user:alice", &local_part, &domain);
    println!(
        "ANPHandleService entry: {}",
        serde_json::to_string_pretty(&handle_service).expect("service entry should serialize"),
    );
}
