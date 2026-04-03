use super::errors::DirectE2eeError;
use super::models::{DirectSessionState, PendingOutboundRecord, SignedPrekey};
use crate::PrivateKeyMaterial;

pub trait IdentityKeyStore {
    fn load_static_key(&self, key_id: &str) -> Result<PrivateKeyMaterial, DirectE2eeError>;
}

pub trait SignedPrekeyStore {
    fn save_signed_prekey(
        &mut self,
        key_id: &str,
        private_key: &PrivateKeyMaterial,
        metadata: &SignedPrekey,
    ) -> Result<(), DirectE2eeError>;

    fn load_signed_prekey(&self, key_id: &str) -> Result<PrivateKeyMaterial, DirectE2eeError>;
}

pub trait SessionStore {
    fn save_session(&mut self, session: &DirectSessionState) -> Result<(), DirectE2eeError>;
    fn load_session(&self, session_id: &str) -> Result<DirectSessionState, DirectE2eeError>;
    fn delete_session(&mut self, session_id: &str) -> Result<(), DirectE2eeError>;
}

pub trait PendingOutboundStore {
    fn save_pending(&mut self, pending: &PendingOutboundRecord) -> Result<(), DirectE2eeError>;
    fn load_pending(&self, operation_id: &str) -> Result<PendingOutboundRecord, DirectE2eeError>;
    fn delete_pending(&mut self, operation_id: &str) -> Result<(), DirectE2eeError>;
}
