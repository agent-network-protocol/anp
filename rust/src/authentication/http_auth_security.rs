//! HTTP authentication policy and replay storage, without network side effects.

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Mutex;

use super::http_signatures::HttpSignatureError;

/// Normalize the credential origin without depending on the network feature.
/// Request URLs must already be serialized by the HTTP adapter (IDNs in ASCII).
pub fn authentication_origin(raw: &str) -> Result<String, HttpSignatureError> {
    let invalid = || HttpSignatureError::InvalidSignatureInput;
    if raw.bytes().any(|b| b <= 32 || b >= 127) || raw.contains('#') || raw.contains('\\') {
        return Err(invalid());
    }
    let (scheme, rest) = raw.split_once("://").ok_or_else(invalid)?;
    if !matches!(scheme, "http" | "https") {
        return Err(invalid());
    }
    let authority = rest.split(['/', '?']).next().ok_or_else(invalid)?;
    if authority.is_empty() || authority.contains('@') {
        return Err(invalid());
    }
    let (host, port) = if let Some(ip) = authority.strip_prefix('[') {
        let (ip, suffix) = ip.split_once(']').ok_or_else(invalid)?;
        let ip: std::net::Ipv6Addr = ip.parse().map_err(|_| invalid())?;
        if ip.to_ipv4_mapped().is_some() {
            return Err(invalid());
        }
        let port = if suffix.is_empty() {
            None
        } else {
            Some(suffix.strip_prefix(':').ok_or_else(invalid)?)
        };
        (format!("[{ip}]"), port)
    } else {
        let (host, port) = match authority.split_once(':') {
            Some((host, port)) => (host, Some(port)),
            None => (authority, None),
        };
        if host.is_empty()
            || host.len() > 253
            || !host
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
        {
            return Err(invalid());
        }
        if host.bytes().all(|b| b.is_ascii_digit() || b == b'.')
            && host.parse::<std::net::Ipv4Addr>().is_err()
        {
            return Err(invalid());
        }
        (host.to_ascii_lowercase(), port)
    };
    let port = match port {
        Some(port) if !port.is_empty() => port.parse::<u16>().map_err(|_| invalid())?,
        Some(_) => return Err(invalid()),
        None => {
            if scheme == "https" {
                443
            } else {
                80
            }
        }
    };
    if port == 0 {
        return Err(invalid());
    }
    Ok(format!("{scheme}://{host}:{port}"))
}

/// Stateless validation policy. Offline crypto verification must opt out explicitly.
#[derive(Debug, Clone, Copy)]
pub struct HttpSignaturePolicy {
    pub max_age_seconds: i64,
    pub future_skew_seconds: i64,
    pub check_time: bool,
}

impl Default for HttpSignaturePolicy {
    fn default() -> Self {
        Self {
            max_age_seconds: 300,
            future_skew_seconds: 60,
            check_time: true,
        }
    }
}

impl HttpSignaturePolicy {
    /// Validate bounded seconds and return the last acceptable timestamp.
    pub fn validate(
        &self,
        created: i64,
        expires: Option<i64>,
        now: i64,
    ) -> Result<i64, HttpSignatureError> {
        if !(1..=86400).contains(&self.max_age_seconds)
            || !(0..=86400).contains(&self.future_skew_seconds)
            || !(0..=999_999_999_999_999).contains(&created)
            || expires.is_some_and(|end| !(created..=999_999_999_999_999).contains(&end))
        {
            return Err(HttpSignatureError::InvalidSignatureInput);
        }
        let deadline = expires
            .unwrap_or(i64::MAX)
            .min(created + self.max_age_seconds);
        if self.check_time
            && (created > now.saturating_add(self.future_skew_seconds) || now > deadline)
        {
            return Err(HttpSignatureError::InvalidSignatureInput);
        }
        Ok(deadline)
    }
}

/// Verified, domain-separated replay facts; never raw signatures or tokens.
#[derive(Debug, Clone)]
pub struct HttpReplayContext {
    pub signer_did: String,
    pub verifier_scope: String,
    pub replay_key: String,
    pub valid_until: i64,
}

/// A storage failure must not fall back to a weaker store or authentication mode.
#[derive(Debug, thiserror::Error)]
#[error("HTTP replay protection unavailable")]
pub struct HttpReplayUnavailable;

/// Non-blocking shared-store adapter supplied by the host application.
pub trait HttpReplayStore: Send + Sync {
    fn consume_once<'a>(
        &'a self,
        context: &'a HttpReplayContext,
    ) -> Pin<Box<dyn Future<Output = Result<bool, HttpReplayUnavailable>> + Send + 'a>>;
}

/// Explicitly process-local store; no cross-process or restart guarantees.
pub struct MemoryHttpReplayStore {
    capacity: usize,
    seen: Mutex<HashMap<String, i64>>,
}

impl Default for MemoryHttpReplayStore {
    fn default() -> Self {
        Self::new(10000)
    }
}

impl MemoryHttpReplayStore {
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity,
            seen: Mutex::new(HashMap::new()),
        }
    }

    /// Frozen-clock entry for unit tests and explicit host clocks.
    pub fn consume_once_at(
        &self,
        context: &HttpReplayContext,
        now: i64,
    ) -> Result<bool, HttpReplayUnavailable> {
        let mut seen = self.seen.lock().map_err(|_| HttpReplayUnavailable)?;
        seen.retain(|_, expiry| *expiry >= now);
        if context.valid_until < now || seen.contains_key(&context.replay_key) {
            return Ok(false);
        }
        if seen.len() >= self.capacity {
            return Err(HttpReplayUnavailable);
        }
        seen.insert(context.replay_key.clone(), context.valid_until);
        Ok(true)
    }
}

impl HttpReplayStore for MemoryHttpReplayStore {
    fn consume_once<'a>(
        &'a self,
        context: &'a HttpReplayContext,
    ) -> Pin<Box<dyn Future<Output = Result<bool, HttpReplayUnavailable>> + Send + 'a>> {
        Box::pin(async move { self.consume_once_at(context, chrono::Utc::now().timestamp()) })
    }
}
