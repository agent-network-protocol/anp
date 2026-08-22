//! Fixed-suite HPKE handoff for secrets crossing an untrusted bridge.

use hpke::{
    aead::ChaCha20Poly1305, kdf::HkdfSha256, kem::X25519HkdfSha256, Deserializable,
    Kem as KemTrait, OpModeR, OpModeS, Serializable,
};
use rand09::{rngs::StdRng, CryptoRng, SeedableRng};
use thiserror::Error;
use zeroize::Zeroizing;

type HandoffKem = X25519HkdfSha256;
type HandoffKdf = HkdfSha256;
type HandoffAead = ChaCha20Poly1305;

/// Protocol identifier for the only supported handoff suite.
pub const SEALED_HANDOFF_SUITE: &str = "hpke-base-x25519-hkdf-sha256-chacha20poly1305-v1";
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
