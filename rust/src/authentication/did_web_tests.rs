use super::{check_resolution_addresses, is_public_address};
use crate::authentication::{DidResolutionAddressPolicy, DidResolutionOptions};

#[test]
fn web_public_addresses() {
    for address in [
        "127.0.0.1",
        "10.0.0.1",
        "169.254.169.254",
        "100.64.0.1",
        "192.168.0.1",
        "198.18.0.1",
        "224.0.0.1",
        "::1",
        "fc00::1",
        "fe80::1",
        "::ffff:127.0.0.1",
        "2002:7f00:1::",
        "2001:db8::1",
        "3fff::1",
    ] {
        assert!(!is_public_address(address.parse().unwrap()), "{address}");
    }
    for address in ["8.8.8.8", "2606:4700:4700::1111"] {
        assert!(is_public_address(address.parse().unwrap()), "{address}");
    }
}

#[test]
fn web_fake_ip_policy_preserves_nonempty_resolution_and_tls_defaults() {
    let options = DidResolutionOptions::default();
    assert!(options.verify_ssl);
    assert!(options.base_url_override.is_none());
    for addresses in [
        vec!["198.18.2.36:443".parse().unwrap()],
        vec!["198.19.255.254:443".parse().unwrap()],
        vec!["[fc00::1]:443".parse().unwrap()],
        vec![
            "8.8.8.8:443".parse().unwrap(),
            "198.18.2.36:443".parse().unwrap(),
        ],
    ] {
        assert!(
            check_resolution_addresses(&addresses, DidResolutionAddressPolicy::HostNetwork).is_ok()
        );
        assert!(
            check_resolution_addresses(&addresses, DidResolutionAddressPolicy::PublicOnly).is_err()
        );
    }
    assert!(check_resolution_addresses(&[], DidResolutionAddressPolicy::HostNetwork).is_err());
}
