use super::errors::DirectE2eeError;
use ring::hmac;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519StaticSecret};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InitialMaterial {
    pub initial_secret: [u8; 32],
    pub root_key: [u8; 32],
    pub chain_key: [u8; 32],
    pub session_id: String,
}

pub fn derive_initial_material_for_initiator(
    sender_static_private: &X25519StaticSecret,
    sender_ephemeral_private: &X25519StaticSecret,
    recipient_static_public: &[u8; 32],
    recipient_signed_prekey_public: &[u8; 32],
) -> Result<InitialMaterial, DirectE2eeError> {
    derive_initial_material_for_initiator_with_opk(
        sender_static_private,
        sender_ephemeral_private,
        recipient_static_public,
        recipient_signed_prekey_public,
        None,
    )
}

pub fn derive_initial_material_for_initiator_with_opk(
    sender_static_private: &X25519StaticSecret,
    sender_ephemeral_private: &X25519StaticSecret,
    recipient_static_public: &[u8; 32],
    recipient_signed_prekey_public: &[u8; 32],
    recipient_one_time_prekey_public: Option<&[u8; 32]>,
) -> Result<InitialMaterial, DirectE2eeError> {
    let recipient_static_public = X25519PublicKey::from(*recipient_static_public);
    let recipient_signed_prekey_public = X25519PublicKey::from(*recipient_signed_prekey_public);
    let dh1 = sender_static_private.diffie_hellman(&recipient_signed_prekey_public);
    let dh2 = sender_ephemeral_private.diffie_hellman(&recipient_static_public);
    let dh3 = sender_ephemeral_private.diffie_hellman(&recipient_signed_prekey_public);
    let mut chunks = vec![
        dh1.to_bytes().to_vec(),
        dh2.to_bytes().to_vec(),
        dh3.to_bytes().to_vec(),
    ];
    if let Some(opk) = recipient_one_time_prekey_public {
        let recipient_opk = X25519PublicKey::from(*opk);
        chunks.push(
            sender_ephemeral_private
                .diffie_hellman(&recipient_opk)
                .to_bytes()
                .to_vec(),
        );
    }
    derive_initial_material(&chunks.iter().map(Vec::as_slice).collect::<Vec<_>>())
}

pub fn derive_initial_material_for_responder(
    recipient_static_private: &X25519StaticSecret,
    recipient_signed_prekey_private: &X25519StaticSecret,
    sender_static_public: &[u8; 32],
    sender_ephemeral_public: &[u8; 32],
) -> Result<InitialMaterial, DirectE2eeError> {
    derive_initial_material_for_responder_with_opk(
        recipient_static_private,
        recipient_signed_prekey_private,
        None,
        sender_static_public,
        sender_ephemeral_public,
    )
}

pub fn derive_initial_material_for_responder_with_opk(
    recipient_static_private: &X25519StaticSecret,
    recipient_signed_prekey_private: &X25519StaticSecret,
    recipient_one_time_prekey_private: Option<&X25519StaticSecret>,
    sender_static_public: &[u8; 32],
    sender_ephemeral_public: &[u8; 32],
) -> Result<InitialMaterial, DirectE2eeError> {
    let sender_static_public = X25519PublicKey::from(*sender_static_public);
    let sender_ephemeral_public = X25519PublicKey::from(*sender_ephemeral_public);
    let dh1 = recipient_signed_prekey_private.diffie_hellman(&sender_static_public);
    let dh2 = recipient_static_private.diffie_hellman(&sender_ephemeral_public);
    let dh3 = recipient_signed_prekey_private.diffie_hellman(&sender_ephemeral_public);
    let mut chunks = vec![
        dh1.to_bytes().to_vec(),
        dh2.to_bytes().to_vec(),
        dh3.to_bytes().to_vec(),
    ];
    if let Some(opk) = recipient_one_time_prekey_private {
        chunks.push(
            opk.diffie_hellman(&sender_ephemeral_public)
                .to_bytes()
                .to_vec(),
        );
    }
    derive_initial_material(&chunks.iter().map(Vec::as_slice).collect::<Vec<_>>())
}

fn derive_initial_material(chunks: &[&[u8]]) -> Result<InitialMaterial, DirectE2eeError> {
    let ikm = chunks
        .iter()
        .flat_map(|chunk| chunk.iter().copied())
        .collect::<Vec<_>>();
    let prk = hkdf_extract(&[0u8; 32], &ikm);
    let initial_secret: [u8; 32] = hkdf_expand_prk(&prk, b"ANP Direct E2EE v1 Initial Secret", 32)?
        .try_into()
        .map_err(|_| DirectE2eeError::crypto("invalid initial secret length"))?;
    let root_key: [u8; 32] = hkdf_expand_prk(&initial_secret, b"ANP Direct E2EE v1 Root Key", 32)?
        .try_into()
        .map_err(|_| DirectE2eeError::crypto("invalid root key length"))?;
    let chain_key: [u8; 32] =
        hkdf_expand_prk(&initial_secret, b"ANP Direct E2EE v1 Chain Key", 32)?
            .try_into()
            .map_err(|_| DirectE2eeError::crypto("invalid chain key length"))?;
    let session_id = crate::keys::base64url_encode(&hkdf_expand_prk(
        &initial_secret,
        b"ANP Direct E2EE v1 Session ID",
        16,
    )?);
    Ok(InitialMaterial {
        initial_secret,
        root_key,
        chain_key,
        session_id,
    })
}

pub(crate) fn hkdf_extract(salt: &[u8], ikm: &[u8]) -> Vec<u8> {
    let key = hmac::Key::new(hmac::HMAC_SHA256, salt);
    hmac::sign(&key, ikm).as_ref().to_vec()
}

pub fn initial_secret_key_and_nonce(
    initial_secret: &[u8; 32],
) -> Result<([u8; 32], [u8; 12]), DirectE2eeError> {
    let chain_key: [u8; 32] = hkdf_expand_prk(initial_secret, b"ANP Direct E2EE v1 Chain Key", 32)?
        .try_into()
        .map_err(|_| DirectE2eeError::crypto("invalid chain key length"))?;
    let step = super::ratchet::derive_chain_step(&chain_key);
    Ok((step.message_key, step.nonce))
}

pub(crate) fn hkdf_expand_prk(
    prk: &[u8],
    info: &[u8],
    len: usize,
) -> Result<Vec<u8>, DirectE2eeError> {
    let mut okm = Vec::with_capacity(len);
    let mut previous = Vec::<u8>::new();
    let mut counter = 1u8;
    while okm.len() < len {
        let key = hmac::Key::new(hmac::HMAC_SHA256, prk);
        let mut ctx = hmac::Context::with_key(&key);
        ctx.update(&previous);
        ctx.update(info);
        ctx.update(&[counter]);
        previous = ctx.sign().as_ref().to_vec();
        okm.extend_from_slice(&previous);
        counter = counter
            .checked_add(1)
            .ok_or_else(|| DirectE2eeError::crypto("hkdf expand overflow"))?;
    }
    okm.truncate(len);
    Ok(okm)
}

#[cfg(test)]
mod tests {
    use super::{derive_initial_material_for_initiator, derive_initial_material_for_responder};
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
    }
}
