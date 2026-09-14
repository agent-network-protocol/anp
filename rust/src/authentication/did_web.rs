//! Strict DID Web resource addressing and bounded public HTTPS retrieval.

use percent_encoding::{percent_decode_str, utf8_percent_encode, AsciiSet, CONTROLS};

use super::did_wba::AuthenticationError;

const SEGMENT_ENCODE: &AsciiSet = &CONTROLS
    .add(b' ')
    .add(b'!')
    .add(b'"')
    .add(b'#')
    .add(b'$')
    .add(b'%')
    .add(b'&')
    .add(b'\'')
    .add(b'(')
    .add(b')')
    .add(b'*')
    .add(b'+')
    .add(b',')
    .add(b'/')
    .add(b':')
    .add(b';')
    .add(b'<')
    .add(b'=')
    .add(b'>')
    .add(b'?')
    .add(b'@')
    .add(b'[')
    .add(b'\\')
    .add(b']')
    .add(b'^')
    .add(b'`')
    .add(b'{')
    .add(b'|')
    .add(b'}');

fn decode_segment(raw: &str) -> Result<String, AuthenticationError> {
    let mut bytes = raw.bytes();
    if raw.is_empty() {
        return Err(AuthenticationError::InvalidDid);
    }
    while let Some(byte) = bytes.next() {
        if byte == b'%' {
            if !bytes.next().is_some_and(|b| b.is_ascii_hexdigit())
                || !bytes.next().is_some_and(|b| b.is_ascii_hexdigit())
            {
                return Err(AuthenticationError::InvalidDid);
            }
        } else if !byte.is_ascii_alphanumeric() && !b"-._~".contains(&byte) {
            return Err(AuthenticationError::InvalidDid);
        }
    }
    percent_decode_str(raw)
        .decode_utf8()
        .map(|s| s.into_owned())
        .map_err(|_| AuthenticationError::InvalidDid)
}

/// Construct the DID Web HTTPS URL without lossy decoding or path normalization.
pub fn build_did_web_resolution_url(did: &str) -> Result<String, AuthenticationError> {
    let parts: Vec<_> = did.split(':').collect();
    if parts.len() < 3 || parts[0] != "did" || parts[1] != "web" {
        return Err(AuthenticationError::InvalidDid);
    }
    let authority = decode_segment(parts[2])?;
    let host_port: Vec<_> = authority.split(':').collect();
    let host = host_port[0];
    let labels: Vec<_> = host.split('.').collect();
    if host_port.len() > 2
        || host.len() > 253
        || labels.len() < 2
        || !labels
            .last()
            .unwrap()
            .bytes()
            .any(|b| b.is_ascii_alphabetic())
        || labels.iter().any(|label| {
            label.is_empty()
                || label.len() > 63
                || !label.as_bytes()[0].is_ascii_alphanumeric()
                || !label.as_bytes()[label.len() - 1].is_ascii_alphanumeric()
                || !label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
    {
        return Err(AuthenticationError::InvalidDid);
    }
    let authority = if host_port.len() == 2 {
        if !host_port[1].bytes().all(|b| b.is_ascii_digit()) {
            return Err(AuthenticationError::InvalidDid);
        }
        let port: u16 = host_port[1]
            .parse()
            .map_err(|_| AuthenticationError::InvalidDid)?;
        if port == 0 {
            return Err(AuthenticationError::InvalidDid);
        }
        format!("{}:{port}", host.to_ascii_lowercase())
    } else {
        host.to_ascii_lowercase()
    };
    let mut segments = Vec::new();
    for raw in &parts[3..] {
        let segment = decode_segment(raw)?;
        if segment == "."
            || segment == ".."
            || segment
                .chars()
                .any(|c| "/\\?#%".contains(c) || c.is_ascii_control())
        {
            return Err(AuthenticationError::InvalidDid);
        }
        segments.push(utf8_percent_encode(&segment, SEGMENT_ENCODE).to_string());
    }
    let path = if segments.is_empty() {
        ".well-known/did.json".to_owned()
    } else {
        format!("{}/did.json", segments.join("/"))
    };
    Ok(format!("https://{authority}/{path}"))
}

#[cfg(feature = "network")]
pub(crate) fn is_public_address(ip: std::net::IpAddr) -> bool {
    use std::net::IpAddr;
    match ip {
        IpAddr::V4(ip) => {
            let [a, b, c, _] = ip.octets();
            !(a == 0
                || a == 10
                || a == 127
                || a >= 224
                || (a == 100 && (64..=127).contains(&b))
                || (a == 169 && b == 254)
                || (a == 172 && (16..=31).contains(&b))
                || (a == 192 && (b == 168 || (b == 0 && (c == 0 || c == 2))))
                || (a == 198 && (b == 18 || b == 19 || (b == 51 && c == 100)))
                || (a == 203 && b == 0 && c == 113))
        }
        IpAddr::V6(ip) => {
            if let Some(v4) = ip.to_ipv4_mapped() {
                return is_public_address(IpAddr::V4(v4));
            }
            let segments = ip.segments();
            (segments[0] & 0xe000) == 0x2000
                && !(segments[0] == 0x2001 && (segments[1] < 0x200 || segments[1] == 0xdb8))
                && segments[0] != 0x2002
                && (segments[0] & 0xfff0) != 0x3ff0
        }
    }
}

#[cfg(all(test, feature = "network"))]
mod tests {
    use super::is_public_address;

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
}

#[cfg(feature = "network")]
pub(crate) async fn fetch_document(
    did: &str,
    options: &super::did_wba::DidResolutionOptions,
) -> Result<serde_json::Value, AuthenticationError> {
    use serde_json::Value;
    use std::{net::SocketAddr, time::Duration};
    const MAX_BYTES: usize = 1024 * 1024;
    if !options.timeout_seconds.is_finite() || options.timeout_seconds <= 0.0 {
        return Err(AuthenticationError::NetworkFailure);
    }
    let timeout = Duration::try_from_secs_f64(options.timeout_seconds)
        .map_err(|_| AuthenticationError::NetworkFailure)?;
    let resource = build_did_web_resolution_url(did)?;
    tokio::time::timeout(timeout, async {
        let mut url = url::Url::parse(&resource).map_err(|_| AuthenticationError::InvalidDid)?;
        let mut builder = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(timeout);
        if let Some(base) = &options.base_url_override {
            let parsed = url::Url::parse(base).map_err(|_| AuthenticationError::InvalidDid)?;
            if !matches!(parsed.scheme(), "http" | "https")
                || parsed.host_str().is_none()
                || !parsed.username().is_empty()
                || parsed.password().is_some()
                || parsed.query().is_some()
                || parsed.fragment().is_some()
            {
                return Err(AuthenticationError::InvalidDid);
            }
            url = url::Url::parse(&format!("{}{}", base.trim_end_matches('/'), url.path()))
                .map_err(|_| AuthenticationError::InvalidDid)?;
            builder = builder.danger_accept_invalid_certs(!options.verify_ssl);
        } else {
            if !options.verify_ssl {
                return Err(AuthenticationError::NetworkFailure);
            }
            let host = url.host_str().ok_or(AuthenticationError::InvalidDid)?;
            let addresses: Vec<SocketAddr> =
                tokio::net::lookup_host((host, url.port_or_known_default().unwrap_or(443)))
                    .await
                    .map_err(|_| AuthenticationError::NetworkFailure)?
                    .collect();
            if addresses.is_empty() || addresses.iter().any(|a| !is_public_address(a.ip())) {
                return Err(AuthenticationError::NetworkFailure);
            }
            // Pin the checked DNS result so the connection cannot re-resolve it.
            builder = builder.resolve_to_addrs(host, &addresses);
        }
        let client = builder
            .build()
            .map_err(|_| AuthenticationError::NetworkFailure)?;
        let mut request = client.get(url).header("Accept", "application/json");
        for (key, value) in &options.headers {
            request = request.header(key, value);
        }
        let mut response = request
            .send()
            .await
            .map_err(|_| AuthenticationError::NetworkFailure)?;
        if response.status() != reqwest::StatusCode::OK
            || response
                .content_length()
                .is_some_and(|length| length > MAX_BYTES as u64)
        {
            return Err(AuthenticationError::NetworkFailure);
        }
        let mut data = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| AuthenticationError::NetworkFailure)?
        {
            if data.len() + chunk.len() > MAX_BYTES {
                return Err(AuthenticationError::NetworkFailure);
            }
            data.extend_from_slice(&chunk);
        }
        let document: Value =
            serde_json::from_slice(&data).map_err(|_| AuthenticationError::JsonFailure)?;
        if document.get("id").and_then(Value::as_str) != Some(did) {
            return Err(AuthenticationError::InvalidDidDocument);
        }
        Ok(document)
    })
    .await
    .map_err(|_| AuthenticationError::NetworkFailure)?
}
