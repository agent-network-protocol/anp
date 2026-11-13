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
#[path = "did_web_tests.rs"]
mod tests;

#[cfg(feature = "network")]
pub(crate) fn check_resolution_addresses(
    addresses: &[std::net::SocketAddr],
    address_policy: super::did_resolver::DidResolutionAddressPolicy,
) -> Result<(), AuthenticationError> {
    if addresses.is_empty()
        || (address_policy == super::did_resolver::DidResolutionAddressPolicy::PublicOnly
            && addresses.iter().any(|a| !is_public_address(a.ip())))
    {
        return Err(AuthenticationError::NetworkFailure);
    }
    Ok(())
}

#[cfg(feature = "network")]
pub(crate) async fn checked_resolution_addresses(
    url: &url::Url,
    policy: super::did_resolver::DidResolutionAddressPolicy,
    timeout: std::time::Duration,
) -> Result<Vec<std::net::SocketAddr>, AuthenticationError> {
    use std::net::SocketAddr;
    let port = url
        .port_or_known_default()
        .ok_or(AuthenticationError::InvalidDid)?;
    let addresses = match url.host().ok_or(AuthenticationError::InvalidDid)? {
        url::Host::Ipv4(ip) => vec![SocketAddr::new(ip.into(), port)],
        url::Host::Ipv6(ip) => vec![SocketAddr::new(ip.into(), port)],
        url::Host::Domain(host) => {
            tokio::time::timeout(timeout, tokio::net::lookup_host((host, port)))
                .await
                .map_err(|_| AuthenticationError::NetworkFailure)?
                .map_err(|_| AuthenticationError::NetworkFailure)?
                .collect()
        }
    };
    check_resolution_addresses(&addresses, policy)?;
    Ok(addresses)
}

#[cfg(feature = "network")]
pub(crate) fn append_bounded_chunk(
    data: &mut Vec<u8>,
    chunk: &[u8],
    limit: usize,
) -> Result<(), AuthenticationError> {
    if data
        .len()
        .checked_add(chunk.len())
        .is_none_or(|length| length > limit)
    {
        return Err(AuthenticationError::NetworkFailure);
    }
    data.extend_from_slice(chunk);
    Ok(())
}

#[cfg(feature = "network")]
pub(crate) async fn fetch_document(
    did: &str,
    options: &super::did_wba::DidResolutionOptions,
    address_policy: super::did_resolver::DidResolutionAddressPolicy,
) -> Result<serde_json::Value, AuthenticationError> {
    let resource = build_did_web_resolution_url(did)?;
    let document = fetch_public_json(&resource, options, address_policy).await?;
    if document.get("id").and_then(serde_json::Value::as_str) != Some(did) {
        return Err(AuthenticationError::InvalidDidDocument);
    }
    Ok(document)
}

#[cfg(feature = "network")]
static PUBLIC_OUTBOUND_REQUESTS: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);
#[cfg(feature = "network")]
pub(crate) struct PublicOutboundPermit(());
#[cfg(feature = "network")]
impl Drop for PublicOutboundPermit {
    fn drop(&mut self) {
        PUBLIC_OUTBOUND_REQUESTS.fetch_sub(1, std::sync::atomic::Ordering::Release);
    }
}
#[cfg(feature = "network")]
pub(crate) fn public_outbound_permit() -> Result<PublicOutboundPermit, AuthenticationError> {
    use std::sync::atomic::Ordering;
    PUBLIC_OUTBOUND_REQUESTS
        .fetch_update(Ordering::AcqRel, Ordering::Relaxed, |active| {
            (active < 32).then_some(active + 1)
        })
        .map(|_| PublicOutboundPermit(()))
        .map_err(|_| AuthenticationError::NetworkFailure)
}

#[cfg(feature = "network")]
pub(crate) async fn fetch_public_json(
    resource: &str,
    options: &super::did_wba::DidResolutionOptions,
    address_policy: super::did_resolver::DidResolutionAddressPolicy,
) -> Result<serde_json::Value, AuthenticationError> {
    use serde_json::Value;
    use std::time::Duration;
    let _permit = public_outbound_permit()?;
    const MAX_BYTES: usize = 1024 * 1024;
    if !options.timeout_seconds.is_finite() || options.timeout_seconds <= 0.0 {
        return Err(AuthenticationError::NetworkFailure);
    }
    let timeout = Duration::try_from_secs_f64(options.timeout_seconds)
        .map_err(|_| AuthenticationError::NetworkFailure)?;
    tokio::time::timeout(timeout, async {
        let mut url = url::Url::parse(resource).map_err(|_| AuthenticationError::InvalidDid)?;
        super::http_auth_security::authentication_origin(resource)
            .map_err(|_| AuthenticationError::InvalidDid)?;
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
            if !options.verify_ssl || url.scheme() != "https" {
                return Err(AuthenticationError::NetworkFailure);
            }
            let host = url.host_str().ok_or(AuthenticationError::InvalidDid)?;
            let addresses = checked_resolution_addresses(&url, address_policy, timeout).await?;
            // Pin this DNS result even when the host allows TUN/Fake-IP mappings.
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
            append_bounded_chunk(&mut data, &chunk, MAX_BYTES)?;
        }
        let document: Value =
            serde_json::from_slice(&data).map_err(|_| AuthenticationError::JsonFailure)?;
        if !document.is_object() {
            return Err(AuthenticationError::InvalidDidDocument);
        }
        Ok(document)
    })
    .await
    .map_err(|_| AuthenticationError::NetworkFailure)?
}
