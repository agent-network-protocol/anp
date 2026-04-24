use super::errors::DirectE2eeError;
use super::x3dh::{hkdf_expand_prk, hkdf_extract};
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, CHACHA20_POLY1305};

pub const MAX_SKIP: u32 = 1000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainStep {
    pub message_key: [u8; 32],
    pub nonce: [u8; 12],
    pub next_chain_key: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RootStep {
    pub root_key: [u8; 32],
    pub chain_key: [u8; 32],
}

pub fn derive_chain_step(chain_key: &[u8; 32]) -> ChainStep {
    let prk = hkdf_extract(&[0u8; 32], chain_key);
    let out = hkdf_expand_prk(&prk, b"ANP Direct E2EE v1 KDF_CK", 76)
        .expect("hkdf expand should support fixed length");
    let mut next_chain_key = [0u8; 32];
    let mut message_key = [0u8; 32];
    let mut nonce = [0u8; 12];
    next_chain_key.copy_from_slice(&out[0..32]);
    message_key.copy_from_slice(&out[32..64]);
    nonce.copy_from_slice(&out[64..76]);
    ChainStep {
        message_key,
        nonce,
        next_chain_key,
    }
}

pub fn derive_root_step(root_key: &[u8; 32], dh_out: &[u8]) -> Result<RootStep, DirectE2eeError> {
    let prk = hkdf_extract(root_key, dh_out);
    let out = hkdf_expand_prk(&prk, b"ANP Direct E2EE v1 KDF_RK", 64)?;
    let mut next_root = [0u8; 32];
    let mut chain_key = [0u8; 32];
    next_root.copy_from_slice(&out[0..32]);
    chain_key.copy_from_slice(&out[32..64]);
    Ok(RootStep {
        root_key: next_root,
        chain_key,
    })
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

#[cfg(test)]
mod tests {
    use super::{decrypt_with_step, derive_chain_step, encrypt_with_step};
    #[test]
    fn chain_step_encrypts_and_decrypts() {
        let step = derive_chain_step(&[9u8; 32]);
        let ciphertext = encrypt_with_step(&step, b"hello", br#"{"aad":true}"#).expect("encrypt");
        let plaintext = decrypt_with_step(&step, &ciphertext, br#"{"aad":true}"#).expect("decrypt");
        assert_eq!(plaintext, b"hello");
    }
}
