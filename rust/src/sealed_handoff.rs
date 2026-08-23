//! Fixed-suite HPKE handoff for secrets crossing an untrusted bridge.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use hpke::{
    aead::ChaCha20Poly1305, kdf::HkdfSha256, kem::X25519HkdfSha256, Deserializable,
    Kem as KemTrait, OpModeR, OpModeS, Serializable,
};
use rand09::{rngs::StdRng, CryptoRng, SeedableRng};
use serde::Serialize;
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use zeroize::Zeroizing;

type HandoffKem = X25519HkdfSha256;
type HandoffKdf = HkdfSha256;
type HandoffAead = ChaCha20Poly1305;

/// Protocol identifier for the only supported handoff suite.
pub const SEALED_HANDOFF_SUITE: &str = "hpke-base-x25519-hkdf-sha256-chacha20poly1305-v1";
/// ANP Identity protocol identifier for sealed secret delivery.
pub const IDENTITY_SEALED_SECRET_PROTOCOL: &str = "anp-sealed-secret/1";
/// Fixed HPKE info bytes for ANP Identity sealed secret delivery.
pub const IDENTITY_SEALED_SECRET_INFO: &[u8] = b"anp.identity.sealed-secret.v1";
/// Active-identity ECDH operation identifier.
pub const IDENTITY_ECDH_OPERATION: &str = "ecdh_sealed";
/// Pending-enrollment ECDH operation identifier.
pub const IDENTITY_ENROLLMENT_ECDH_OPERATION: &str = "enrollment_ecdh_sealed";
/// User-confirmed legacy Root export operation identifier.
pub const IDENTITY_ROOT_EXPORT_OPERATION: &str = "export_root_key_sealed";
/// Capability required by both active and enrollment ECDH.
pub const IDENTITY_ECDH_CAPABILITY: &str = "IDENTITY_ECDH_SEALED";
/// Capability required by the AWiki legacy Root transfer exception.
pub const IDENTITY_ROOT_EXPORT_CAPABILITY: &str = "AWIKI_LEGACY_ROOT_TRANSFER_V1";
/// Maximum secret payload accepted by the handoff helper.
pub const MAX_SEALED_HANDOFF_PLAINTEXT_BYTES: usize = 4 * 1024 * 1024;

const MAX_CONTEXT_BYTES: usize = u16::MAX as usize - 5;
const X25519_KEY_BYTES: usize = 32;

/// Recipient key material whose private bytes are zeroized on drop.
pub struct SealedHandoffRecipient {
    private_key: Zeroizing<[u8; X25519_KEY_BYTES]>,
    public_key: [u8; X25519_KEY_BYTES],
}

/// One HPKE Base-mode ciphertext. It contains no plaintext secret material.
#[derive(Clone, PartialEq, Eq)]
pub struct SealedHandoff {
    encapped_key: [u8; X25519_KEY_BYTES],
    ciphertext: Vec<u8>,
}

/// Public identity fields bound into one sealed operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedIdentityContext {
    pub store_id: String,
    pub identity_id: String,
    pub did: String,
}

/// Public authorization fields authenticated by a sealed delivery's AAD.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedAuthorizationContext {
    pub provider_instance_id: String,
    pub parent_lease_id: String,
    pub consumer: String,
    pub capability: String,
    pub store_id: String,
    pub expires_at: i64,
}

/// Canonical request binding shared by the provider and native host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedOperationBinding {
    pub capability: String,
    pub identity_id: String,
    pub operation: String,
    pub kid: String,
    pub request_id: String,
    pub recipient_public_key: [u8; X25519_KEY_BYTES],
    pub operation_input_digest: String,
}

/// Redacted, stable failures for the sealed handoff boundary.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum SealedHandoffError {
    /// A public/private/encapsulated key has an invalid encoding or length.
    #[error("the sealed handoff key is invalid")]
    InvalidKey,
    /// Info, AAD, or plaintext exceeds the fixed implementation limits.
    #[error("the sealed handoff input exceeds its limit")]
    InputTooLarge,
    /// HPKE setup, authentication, or decryption failed.
    #[error("the sealed handoff operation failed")]
    Crypto,
    /// Required identity, authorization, or operation context is inconsistent.
    #[error("the sealed handoff context is invalid")]
    InvalidContext,
}

/// Builds the shared request binding for active-identity X25519 agreement.
pub fn identity_ecdh_binding(
    identity: &SealedIdentityContext,
    kid: &str,
    peer_public: &[u8; X25519_KEY_BYTES],
    recipient_public_key: &[u8; X25519_KEY_BYTES],
    request_id: &str,
) -> Result<SealedOperationBinding, SealedHandoffError> {
    validate_operation_context(identity, kid, request_id)?;
    #[derive(Serialize)]
    struct DigestInput<'a> {
        protocol: &'static str,
        operation: &'static str,
        store_id: &'a str,
        identity_id: &'a str,
        did: &'a str,
        kid: &'a str,
        algorithm: &'static str,
        peer_public_b64u: String,
        recipient_public_key_digest: String,
        request_id: &'a str,
    }
    let digest = sealed_operation_digest(&DigestInput {
        protocol: IDENTITY_SEALED_SECRET_PROTOCOL,
        operation: IDENTITY_ECDH_OPERATION,
        store_id: &identity.store_id,
        identity_id: &identity.identity_id,
        did: &identity.did,
        kid,
        algorithm: "X25519",
        peer_public_b64u: URL_SAFE_NO_PAD.encode(peer_public),
        recipient_public_key_digest: sealed_recipient_public_key_digest(recipient_public_key),
        request_id,
    })?;
    Ok(operation_binding(
        IDENTITY_ECDH_CAPABILITY,
        IDENTITY_ECDH_OPERATION,
        identity,
        kid,
        recipient_public_key,
        request_id,
        digest,
    ))
}

/// Builds the shared request binding for pending-enrollment X25519 agreement.
pub fn identity_enrollment_ecdh_binding(
    identity: &SealedIdentityContext,
    enrollment_id: &str,
    kid: &str,
    peer_public: &[u8; X25519_KEY_BYTES],
    recipient_public_key: &[u8; X25519_KEY_BYTES],
    request_id: &str,
) -> Result<SealedOperationBinding, SealedHandoffError> {
    validate_operation_context(identity, kid, request_id)?;
    if enrollment_id.trim().is_empty() {
        return Err(SealedHandoffError::InvalidContext);
    }
    #[derive(Serialize)]
    struct DigestInput<'a> {
        protocol: &'static str,
        operation: &'static str,
        store_id: &'a str,
        identity_id: &'a str,
        did: &'a str,
        enrollment_id: &'a str,
        kid: &'a str,
        algorithm: &'static str,
        peer_public_b64u: String,
        recipient_public_key_digest: String,
        request_id: &'a str,
    }
    let digest = sealed_operation_digest(&DigestInput {
        protocol: IDENTITY_SEALED_SECRET_PROTOCOL,
        operation: IDENTITY_ENROLLMENT_ECDH_OPERATION,
        store_id: &identity.store_id,
        identity_id: &identity.identity_id,
        did: &identity.did,
        enrollment_id,
        kid,
        algorithm: "X25519",
        peer_public_b64u: URL_SAFE_NO_PAD.encode(peer_public),
        recipient_public_key_digest: sealed_recipient_public_key_digest(recipient_public_key),
        request_id,
    })?;
    Ok(operation_binding(
        IDENTITY_ECDH_CAPABILITY,
        IDENTITY_ENROLLMENT_ECDH_OPERATION,
        identity,
        kid,
        recipient_public_key,
        request_id,
        digest,
    ))
}

/// Builds the shared request binding for user-confirmed legacy Root export.
pub fn identity_root_export_binding(
    identity: &SealedIdentityContext,
    kid: &str,
    recipient_public_key: &[u8; X25519_KEY_BYTES],
    request_id: &str,
    user_presence_confirmed: bool,
) -> Result<SealedOperationBinding, SealedHandoffError> {
    validate_operation_context(identity, kid, request_id)?;
    if !user_presence_confirmed {
        return Err(SealedHandoffError::InvalidContext);
    }
    #[derive(Serialize)]
    struct DigestInput<'a> {
        protocol: &'static str,
        operation: &'static str,
        store_id: &'a str,
        identity_id: &'a str,
        did: &'a str,
        kid: &'a str,
        recipient_public_key_digest: String,
        request_id: &'a str,
        user_presence_confirmed: bool,
    }
    let digest = sealed_operation_digest(&DigestInput {
        protocol: IDENTITY_SEALED_SECRET_PROTOCOL,
        operation: IDENTITY_ROOT_EXPORT_OPERATION,
        store_id: &identity.store_id,
        identity_id: &identity.identity_id,
        did: &identity.did,
        kid,
        recipient_public_key_digest: sealed_recipient_public_key_digest(recipient_public_key),
        request_id,
        user_presence_confirmed,
    })?;
    Ok(operation_binding(
        IDENTITY_ROOT_EXPORT_CAPABILITY,
        IDENTITY_ROOT_EXPORT_OPERATION,
        identity,
        kid,
        recipient_public_key,
        request_id,
        digest,
    ))
}

/// Produces the exact canonical AAD authenticated by a sealed delivery.
pub fn identity_operation_aad(
    authorization: &SealedAuthorizationContext,
    binding: &SealedOperationBinding,
    identity: &SealedIdentityContext,
) -> Result<Vec<u8>, SealedHandoffError> {
    if authorization.store_id != identity.store_id
        || authorization.capability != binding.capability
        || binding.identity_id != identity.identity_id
        || authorization.provider_instance_id.trim().is_empty()
        || authorization.parent_lease_id.trim().is_empty()
        || authorization.consumer.trim().is_empty()
        || authorization.expires_at <= 0
    {
        return Err(SealedHandoffError::InvalidContext);
    }
    #[derive(Serialize)]
    struct Aad<'a> {
        protocol_version: &'static str,
        operation: &'a str,
        provider_instance_id: &'a str,
        parent_lease_id: &'a str,
        consumer: &'a str,
        capability: &'a str,
        store_id: &'a str,
        identity_id: &'a str,
        kid: &'a str,
        request_id: &'a str,
        recipient_public_key_digest: String,
        canonical_request_digest: &'a str,
    }
    serde_json_canonicalizer::to_vec(&Aad {
        protocol_version: IDENTITY_SEALED_SECRET_PROTOCOL,
        operation: &binding.operation,
        provider_instance_id: &authorization.provider_instance_id,
        parent_lease_id: &authorization.parent_lease_id,
        consumer: &authorization.consumer,
        capability: &authorization.capability,
        store_id: &identity.store_id,
        identity_id: &identity.identity_id,
        kid: &binding.kid,
        request_id: &binding.request_id,
        recipient_public_key_digest: sealed_recipient_public_key_digest(
            &binding.recipient_public_key,
        ),
        canonical_request_digest: &binding.operation_input_digest,
    })
    .map_err(|_| SealedHandoffError::InvalidContext)
}

/// Stable digest of an HPKE recipient public key used by operation tokens and AAD.
pub fn sealed_recipient_public_key_digest(public_key: &[u8; X25519_KEY_BYTES]) -> String {
    let mut digest = Sha256::new();
    digest.update(b"anp.identity.recipient-public-key.v1\0");
    digest.update(public_key);
    format!("sha256:{}", URL_SAFE_NO_PAD.encode(digest.finalize()))
}

fn operation_binding(
    capability: &str,
    operation: &str,
    identity: &SealedIdentityContext,
    kid: &str,
    recipient_public_key: &[u8; X25519_KEY_BYTES],
    request_id: &str,
    operation_input_digest: String,
) -> SealedOperationBinding {
    SealedOperationBinding {
        capability: capability.to_owned(),
        identity_id: identity.identity_id.clone(),
        operation: operation.to_owned(),
        kid: kid.to_owned(),
        request_id: request_id.to_owned(),
        recipient_public_key: *recipient_public_key,
        operation_input_digest,
    }
}

fn sealed_operation_digest(value: &impl Serialize) -> Result<String, SealedHandoffError> {
    let canonical =
        serde_json_canonicalizer::to_vec(value).map_err(|_| SealedHandoffError::InvalidContext)?;
    let mut digest = Sha256::new();
    digest.update(b"anp.identity.sealed-operation.v1\0");
    digest.update(canonical);
    Ok(format!(
        "sha256:{}",
        URL_SAFE_NO_PAD.encode(digest.finalize())
    ))
}

fn validate_operation_context(
    identity: &SealedIdentityContext,
    kid: &str,
    request_id: &str,
) -> Result<(), SealedHandoffError> {
    if identity.store_id.trim().is_empty()
        || identity.identity_id.trim().is_empty()
        || identity.did.trim().is_empty()
        || kid.trim().is_empty()
        || request_id.trim().is_empty()
    {
        return Err(SealedHandoffError::InvalidContext);
    }
    Ok(())
}

impl SealedHandoffRecipient {
    /// Generates a fresh ephemeral recipient key pair from the operating-system RNG.
    pub fn generate() -> Self {
        let mut rng = StdRng::from_os_rng();
        Self::generate_with_rng(&mut rng)
    }

    /// Restores recipient key material from exactly 32 private X25519 bytes.
    pub fn from_private_key(
        private_key: Zeroizing<[u8; X25519_KEY_BYTES]>,
    ) -> Result<Self, SealedHandoffError> {
        let private = <HandoffKem as KemTrait>::PrivateKey::from_bytes(private_key.as_ref())
            .map_err(|_| SealedHandoffError::InvalidKey)?;
        let serialized_public = HandoffKem::sk_to_pk(&private).to_bytes();
        let public_key = copy_x25519_bytes(serialized_public.as_ref())?;
        Ok(Self {
            private_key,
            public_key,
        })
    }

    /// Returns the public recipient key safe to carry through TypeScript.
    pub fn public_key(&self) -> &[u8; X25519_KEY_BYTES] {
        &self.public_key
    }

    /// Opens one ciphertext bound to the exact info and AAD bytes.
    pub fn open(
        &self,
        message: &SealedHandoff,
        info: &[u8],
        aad: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, SealedHandoffError> {
        validate_context(info, aad)?;
        let private = <HandoffKem as KemTrait>::PrivateKey::from_bytes(self.private_key.as_ref())
            .map_err(|_| SealedHandoffError::InvalidKey)?;
        let encapped = <HandoffKem as KemTrait>::EncappedKey::from_bytes(&message.encapped_key)
            .map_err(|_| SealedHandoffError::InvalidKey)?;
        let mut receiver = hpke::setup_receiver::<HandoffAead, HandoffKdf, HandoffKem>(
            &OpModeR::Base,
            &private,
            &encapped,
            info,
        )
        .map_err(|_| SealedHandoffError::Crypto)?;
        receiver
            .open(&message.ciphertext, aad)
            .map(Zeroizing::new)
            .map_err(|_| SealedHandoffError::Crypto)
    }

    fn generate_with_rng(rng: &mut impl CryptoRng) -> Self {
        let (private, public) = HandoffKem::gen_keypair(rng);
        let serialized_private = private.to_bytes();
        let private_key = Zeroizing::new(
            copy_x25519_bytes(serialized_private.as_ref())
                .expect("X25519 private keys are exactly 32 bytes"),
        );
        let serialized_public = public.to_bytes();
        let public_key = copy_x25519_bytes(serialized_public.as_ref())
            .expect("X25519 public keys are exactly 32 bytes");
        Self {
            private_key,
            public_key,
        }
    }
}

impl SealedHandoff {
    /// Seals secret bytes to one exact recipient, info string, and AAD value.
    pub fn seal(
        recipient_public_key: &[u8],
        info: &[u8],
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<Self, SealedHandoffError> {
        let mut rng = StdRng::from_os_rng();
        Self::seal_with_rng(recipient_public_key, info, aad, plaintext, &mut rng)
    }

    /// Returns the serialized encapsulated X25519 key.
    pub fn encapped_key(&self) -> &[u8; X25519_KEY_BYTES] {
        &self.encapped_key
    }

    /// Returns the authenticated ciphertext, including its AEAD tag.
    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }

    /// Reconstructs a ciphertext received from a provider DTO.
    pub fn from_parts(
        encapped_key: &[u8],
        ciphertext: Vec<u8>,
    ) -> Result<Self, SealedHandoffError> {
        let encapped_key = encapped_key
            .try_into()
            .map_err(|_| SealedHandoffError::InvalidKey)?;
        if ciphertext.len() < 16 {
            return Err(SealedHandoffError::Crypto);
        }
        if ciphertext.len() > MAX_SEALED_HANDOFF_PLAINTEXT_BYTES + 16 {
            return Err(SealedHandoffError::InputTooLarge);
        }
        Ok(Self {
            encapped_key,
            ciphertext,
        })
    }

    fn seal_with_rng(
        recipient_public_key: &[u8],
        info: &[u8],
        aad: &[u8],
        plaintext: &[u8],
        rng: &mut impl CryptoRng,
    ) -> Result<Self, SealedHandoffError> {
        validate_context(info, aad)?;
        if plaintext.len() > MAX_SEALED_HANDOFF_PLAINTEXT_BYTES {
            return Err(SealedHandoffError::InputTooLarge);
        }
        let recipient = <HandoffKem as KemTrait>::PublicKey::from_bytes(recipient_public_key)
            .map_err(|_| SealedHandoffError::InvalidKey)?;
        let (encapped, mut sender) = hpke::setup_sender::<HandoffAead, HandoffKdf, HandoffKem, _>(
            &OpModeS::Base,
            &recipient,
            info,
            rng,
        )
        .map_err(|_| SealedHandoffError::Crypto)?;
        let ciphertext = sender
            .seal(plaintext, aad)
            .map_err(|_| SealedHandoffError::Crypto)?;
        let serialized_encapped = encapped.to_bytes();
        let encapped_key = copy_x25519_bytes(serialized_encapped.as_ref())?;
        Ok(Self {
            encapped_key,
            ciphertext,
        })
    }
}

fn validate_context(info: &[u8], aad: &[u8]) -> Result<(), SealedHandoffError> {
    if info.len() > MAX_CONTEXT_BYTES || aad.len() > MAX_CONTEXT_BYTES {
        return Err(SealedHandoffError::InputTooLarge);
    }
    Ok(())
}

fn copy_x25519_bytes(bytes: &[u8]) -> Result<[u8; X25519_KEY_BYTES], SealedHandoffError> {
    bytes.try_into().map_err(|_| SealedHandoffError::InvalidKey)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_suite_roundtrips_in_both_directions_and_binds_aad() {
        let vector: TestVector =
            serde_json::from_str(include_str!("../tests/fixtures/sealed_handoff_v1.json")).unwrap();
        let mut recipient_rng = StdRng::seed_from_u64(0xA11C_E001);
        let recipient = SealedHandoffRecipient::generate_with_rng(&mut recipient_rng);
        let mut sender_rng = StdRng::seed_from_u64(0xA11C_E002);
        let sealed = SealedHandoff::seal_with_rng(
            recipient.public_key(),
            b"anp.identity.sealed-handoff.v1",
            b"provider=fixture;operation=forward",
            b"private-key-material",
            &mut sender_rng,
        )
        .unwrap();

        let plaintext = recipient
            .open(
                &sealed,
                b"anp.identity.sealed-handoff.v1",
                b"provider=fixture;operation=forward",
            )
            .unwrap();
        assert_eq!(
            encode_hex(recipient.public_key()),
            vector.recipient_public_key_hex
        );
        assert_eq!(encode_hex(sealed.encapped_key()), vector.encapped_key_hex);
        assert_eq!(encode_hex(sealed.ciphertext()), vector.ciphertext_hex);
        assert_eq!(vector.suite, SEALED_HANDOFF_SUITE);

        let private_key: [u8; 32] = decode_hex(&vector.recipient_private_key_hex)
            .try_into()
            .unwrap();
        let vector_recipient =
            SealedHandoffRecipient::from_private_key(Zeroizing::new(private_key)).unwrap();
        let vector_sealed = SealedHandoff::from_parts(
            &decode_hex(&vector.encapped_key_hex),
            decode_hex(&vector.ciphertext_hex),
        )
        .unwrap();
        assert_eq!(
            vector_recipient
                .open(
                    &vector_sealed,
                    vector.info_utf8.as_bytes(),
                    vector.aad_utf8.as_bytes(),
                )
                .unwrap()
                .as_slice(),
            vector.plaintext_utf8.as_bytes()
        );
        assert_eq!(plaintext.as_slice(), b"private-key-material");
        assert_eq!(sealed.encapped_key().len(), 32);
        assert_eq!(
            sealed.ciphertext().len(),
            b"private-key-material".len() + 16
        );

        assert!(matches!(
            recipient.open(
                &sealed,
                b"anp.identity.sealed-handoff.v1",
                b"provider=fixture;operation=reverse",
            ),
            Err(SealedHandoffError::Crypto)
        ));

        let reverse = SealedHandoffRecipient::generate();
        let sealed_reverse = SealedHandoff::seal(
            reverse.public_key(),
            b"anp.identity.sealed-handoff.v1",
            b"provider=fixture;operation=reverse",
            b"shared-secret",
        )
        .unwrap();
        assert_eq!(
            reverse
                .open(
                    &sealed_reverse,
                    b"anp.identity.sealed-handoff.v1",
                    b"provider=fixture;operation=reverse",
                )
                .unwrap()
                .as_slice(),
            b"shared-secret"
        );
    }

    #[test]
    fn malformed_keys_tampering_and_oversized_inputs_fail_closed() {
        let recipient = SealedHandoffRecipient::generate();
        assert!(matches!(
            SealedHandoff::seal(&[0; 31], b"info", b"aad", b"secret"),
            Err(SealedHandoffError::InvalidKey)
        ));

        let mut sealed =
            SealedHandoff::seal(recipient.public_key(), b"info", b"aad", b"secret").unwrap();
        sealed.ciphertext[0] ^= 1;
        assert!(matches!(
            recipient.open(&sealed, b"info", b"aad"),
            Err(SealedHandoffError::Crypto)
        ));
        assert!(matches!(
            SealedHandoff::seal(
                recipient.public_key(),
                &vec![0; MAX_CONTEXT_BYTES + 1],
                b"aad",
                b"secret",
            ),
            Err(SealedHandoffError::InputTooLarge)
        ));
        assert!(matches!(
            SealedHandoff::from_parts(&[0; 32], vec![0; 15]),
            Err(SealedHandoffError::Crypto)
        ));
    }

    #[test]
    fn identity_operation_contract_binds_request_authorization_and_recipient() {
        let identity = SealedIdentityContext {
            store_id: "store-1".to_owned(),
            identity_id: "identity-1".to_owned(),
            did: "did:wba:example.test:alice".to_owned(),
        };
        let recipient = SealedHandoffRecipient::generate();
        let binding = identity_ecdh_binding(
            &identity,
            "did:wba:example.test:alice#agreement",
            &[0x31; 32],
            recipient.public_key(),
            "request-1",
        )
        .unwrap();
        let authorization = SealedAuthorizationContext {
            provider_instance_id: "provider-1".to_owned(),
            parent_lease_id: "lease-1".to_owned(),
            consumer: "dsh-awiki".to_owned(),
            capability: IDENTITY_ECDH_CAPABILITY.to_owned(),
            store_id: identity.store_id.clone(),
            expires_at: 2_000_000_000,
        };
        let aad = identity_operation_aad(&authorization, &binding, &identity).unwrap();
        let sealed = SealedHandoff::seal(
            recipient.public_key(),
            IDENTITY_SEALED_SECRET_INFO,
            &aad,
            &[0x42; 32],
        )
        .unwrap();
        assert_eq!(
            recipient
                .open(&sealed, IDENTITY_SEALED_SECRET_INFO, &aad)
                .unwrap()
                .as_slice(),
            &[0x42; 32]
        );

        let mut changed = binding.clone();
        changed.request_id = "request-2".to_owned();
        assert_ne!(
            identity_operation_aad(&authorization, &changed, &identity).unwrap(),
            aad
        );
        let mut wrong_capability = authorization;
        wrong_capability.capability = IDENTITY_ROOT_EXPORT_CAPABILITY.to_owned();
        assert_eq!(
            identity_operation_aad(&wrong_capability, &binding, &identity).unwrap_err(),
            SealedHandoffError::InvalidContext
        );
    }

    fn encode_hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    fn decode_hex(value: &str) -> Vec<u8> {
        assert_eq!(value.len() % 2, 0);
        value
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect()
    }

    #[derive(serde::Deserialize)]
    struct TestVector {
        suite: String,
        recipient_private_key_hex: String,
        recipient_public_key_hex: String,
        encapped_key_hex: String,
        ciphertext_hex: String,
        info_utf8: String,
        aad_utf8: String,
        plaintext_utf8: String,
    }
}
