use super::errors::DirectE2eeError;
use ring::hkdf;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519StaticSecret};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InitialMaterial {
    pub initial_secret: [u8; 32],
    pub root_key: [u8; 32],
    pub initiator_chain_key: [u8; 32],
    pub responder_chain_key: [u8; 32],
    pub session_id: String,
}

pub fn derive_initial_material_for_initiator(
    sender_static_private: &X25519StaticSecret,
    sender_ephemeral_private: &X25519StaticSecret,
    recipient_static_public: &[u8; 32],
    recipient_signed_prekey_public: &[u8; 32],
) -> Result<InitialMaterial, DirectE2eeError> {
    let recipient_static_public = X25519PublicKey::from(*recipient_static_public);
    let recipient_signed_prekey_public = X25519PublicKey::from(*recipient_signed_prekey_public);
    let dh1 = sender_static_private.diffie_hellman(&recipient_signed_prekey_public);
    let dh2 = sender_ephemeral_private.diffie_hellman(&recipient_static_public);
    let dh3 = sender_ephemeral_private.diffie_hellman(&recipient_signed_prekey_public);
    derive_initial_material(&[&dh1.to_bytes(), &dh2.to_bytes(), &dh3.to_bytes()])
}

pub fn derive_initial_material_for_responder(
    recipient_static_private: &X25519StaticSecret,
    recipient_signed_prekey_private: &X25519StaticSecret,
    sender_static_public: &[u8; 32],
    sender_ephemeral_public: &[u8; 32],
) -> Result<InitialMaterial, DirectE2eeError> {
    let sender_static_public = X25519PublicKey::from(*sender_static_public);
    let sender_ephemeral_public = X25519PublicKey::from(*sender_ephemeral_public);
    let dh1 = recipient_signed_prekey_private.diffie_hellman(&sender_static_public);
    let dh2 = recipient_static_private.diffie_hellman(&sender_ephemeral_public);
    let dh3 = recipient_signed_prekey_private.diffie_hellman(&sender_ephemeral_public);
    derive_initial_material(&[&dh1.to_bytes(), &dh2.to_bytes(), &dh3.to_bytes()])
}

pub fn initial_secret_key_and_nonce(
    initial_secret: &[u8; 32],
) -> Result<([u8; 32], [u8; 12]), DirectE2eeError> {
    Ok((
        hkdf_expand(initial_secret, b"ANP Direct E2EE v1 Init AEAD Key", 32)?
            .try_into()
            .map_err(|_| DirectE2eeError::crypto("invalid init key length"))?,
        hkdf_expand(initial_secret, b"ANP Direct E2EE v1 Init AEAD Nonce", 12)?
            .try_into()
            .map_err(|_| DirectE2eeError::crypto("invalid init nonce length"))?,
    ))
}

fn derive_initial_material(chunks: &[&[u8]]) -> Result<InitialMaterial, DirectE2eeError> {
    let ikm = chunks
        .iter()
        .flat_map(|chunk| chunk.iter().copied())
        .collect::<Vec<_>>();
    let initial_secret = hkdf_expand_from_ikm(&ikm, b"ANP Direct E2EE v1 Initial Secret", 32)?;
    let initial_secret: [u8; 32] = initial_secret
        .try_into()
        .map_err(|_| DirectE2eeError::crypto("invalid initial secret length"))?;
    let root_key = hkdf_expand(&initial_secret, b"ANP Direct E2EE v1 Root Key", 32)?;
    let initiator_chain_key = hkdf_expand(
        &initial_secret,
        b"ANP Direct E2EE v1 Initiator Chain Key",
        32,
    )?;
    let responder_chain_key = hkdf_expand(
        &initial_secret,
        b"ANP Direct E2EE v1 Responder Chain Key",
        32,
    )?;
    let session_id = crate::keys::base64url_encode(&hkdf_expand(
        &initial_secret,
        b"ANP Direct E2EE v1 Session ID",
        16,
    )?);
    Ok(InitialMaterial {
        initial_secret,
        root_key: root_key
            .try_into()
            .map_err(|_| DirectE2eeError::crypto("invalid root key length"))?,
        initiator_chain_key: initiator_chain_key
            .try_into()
            .map_err(|_| DirectE2eeError::crypto("invalid initiator chain key length"))?,
        responder_chain_key: responder_chain_key
            .try_into()
            .map_err(|_| DirectE2eeError::crypto("invalid responder chain key length"))?,
        session_id,
    })
}

fn hkdf_expand_from_ikm(ikm: &[u8], info: &[u8], len: usize) -> Result<Vec<u8>, DirectE2eeError> {
    let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, &[0u8; 32]);
    let prk = salt.extract(ikm);
    let info_parts = [info];
    let okm = prk
        .expand(&info_parts, HkdfLen(len))
        .map_err(|_| DirectE2eeError::crypto("hkdf expand failed"))?;
    let mut output = vec![0u8; len];
    okm.fill(&mut output)
        .map_err(|_| DirectE2eeError::crypto("hkdf fill failed"))?;
    Ok(output)
}

fn hkdf_expand(secret: &[u8; 32], info: &[u8], len: usize) -> Result<Vec<u8>, DirectE2eeError> {
    hkdf_expand_from_ikm(secret, info, len)
}

#[derive(Clone, Copy)]
struct HkdfLen(usize);

impl hkdf::KeyType for HkdfLen {
    fn len(&self) -> usize {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use super::{
        derive_initial_material_for_initiator, derive_initial_material_for_responder,
        initial_secret_key_and_nonce,
    };
    use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519StaticSecret};

    #[test]
    fn initiator_and_responder_derive_the_same_initial_secret() {
        let sender_static = X25519StaticSecret::from([1u8; 32]);
        let sender_ephemeral = X25519StaticSecret::from([2u8; 32]);
        let recipient_static = X25519StaticSecret::from([3u8; 32]);
        let recipient_signed_prekey = X25519StaticSecret::from([4u8; 32]);

        let initiator = derive_initial_material_for_initiator(
            &sender_static,
            &sender_ephemeral,
            &X25519PublicKey::from(&recipient_static).to_bytes(),
            &X25519PublicKey::from(&recipient_signed_prekey).to_bytes(),
        )
        .expect("initiator material");
        let responder = derive_initial_material_for_responder(
            &recipient_static,
            &recipient_signed_prekey,
            &X25519PublicKey::from(&sender_static).to_bytes(),
            &X25519PublicKey::from(&sender_ephemeral).to_bytes(),
        )
        .expect("responder material");

        assert_eq!(initiator.initial_secret, responder.initial_secret);
        assert_eq!(initiator.session_id, responder.session_id);

        let (key, nonce) = initial_secret_key_and_nonce(&initiator.initial_secret)
            .expect("init secret key and nonce");
        assert_eq!(key.len(), 32);
        assert_eq!(nonce.len(), 12);
    }
}
