use super::errors::DirectE2eeError;
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, CHACHA20_POLY1305};
use sha2::{Digest, Sha256};

pub const MAX_SKIP: u32 = 1000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainStep {
    pub message_key: [u8; 32],
    pub nonce: [u8; 12],
    pub next_chain_key: [u8; 32],
}

pub fn derive_chain_step(chain_key: &[u8; 32]) -> ChainStep {
    let next_chain_key = digest_with_label(chain_key, b"ANP Direct E2EE v1 Next Chain Key");
    let message_key = digest_with_label(chain_key, b"ANP Direct E2EE v1 Message Key");
    let nonce_material = digest_with_label(chain_key, b"ANP Direct E2EE v1 Message Nonce");
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&nonce_material[..12]);
    ChainStep {
        message_key,
        nonce,
        next_chain_key,
    }
}

pub fn encrypt_with_step(
    step: &ChainStep,
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, DirectE2eeError> {
    let unbound = UnboundKey::new(&CHACHA20_POLY1305, &step.message_key)
        .map_err(|_| DirectE2eeError::crypto("invalid ChaCha20-Poly1305 key"))?;
    let key = LessSafeKey::new(unbound);
    let nonce = Nonce::assume_unique_for_key(step.nonce);
    let mut buffer = plaintext.to_vec();
    key.seal_in_place_append_tag(nonce, Aad::from(aad), &mut buffer)
        .map_err(|_| DirectE2eeError::crypto("failed to encrypt ciphertext"))?;
    Ok(buffer)
}

pub fn decrypt_with_step(
    step: &ChainStep,
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, DirectE2eeError> {
    let unbound = UnboundKey::new(&CHACHA20_POLY1305, &step.message_key)
        .map_err(|_| DirectE2eeError::crypto("invalid ChaCha20-Poly1305 key"))?;
    let key = LessSafeKey::new(unbound);
    let nonce = Nonce::assume_unique_for_key(step.nonce);
    let mut buffer = ciphertext.to_vec();
    let plaintext = key
        .open_in_place(nonce, Aad::from(aad), &mut buffer)
        .map_err(|_| DirectE2eeError::crypto("failed to decrypt ciphertext"))?;
    Ok(plaintext.to_vec())
}

fn digest_with_label(chain_key: &[u8; 32], label: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(label);
    hasher.update(chain_key);
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::{decrypt_with_step, derive_chain_step, encrypt_with_step};

    #[test]
    fn chain_step_encrypts_and_decrypts() {
        let step = derive_chain_step(&[9u8; 32]);
        let ciphertext = encrypt_with_step(&step, b"hello", br#"{"aad":true}"#)
            .expect("encrypt");
        let plaintext = decrypt_with_step(&step, &ciphertext, br#"{"aad":true}"#)
            .expect("decrypt");
        assert_eq!(plaintext, b"hello");
    }
}
