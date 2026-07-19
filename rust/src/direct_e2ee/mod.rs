pub mod aad;
pub mod bundle;
pub mod envelope;
pub mod errors;
pub mod helpers;
pub mod models;
pub mod ratchet;
pub mod session;
pub mod store;
pub mod v2_aad;
pub mod v2_bundle;
pub mod v2_errors;
pub mod v2_models;
pub mod v2_session;
pub mod v2_wire;
pub mod x3dh;

pub use aad::{build_init_aad, build_message_aad};
pub use bundle::{
    build_prekey_bundle, checked_prekey_bundle_get_request, extract_x25519_public_key,
    prekey_bundle_get_body, prekey_bundle_get_request, prekey_bundle_publish_body,
    prekey_bundle_publish_request, should_retry_without_opk, should_retry_without_opk_message,
    signed_prekey_from_private_key, validate_prekey_bundle_get_operation_id, verify_prekey_bundle,
};
pub use envelope::{
    direct_body_from_content_type, direct_cipher_body_from_value, direct_cipher_body_to_value,
    direct_cipher_send_request, direct_init_body_from_value, direct_init_body_to_value,
    direct_init_send_request, direct_notification_from_message_view,
    direct_notifications_from_history_page, direct_send_params, direct_send_request,
    direct_send_request_from_pending, is_direct_e2ee_wire_content_type, plaintext_to_value,
    validate_direct_send_ids, DirectEnvelopeBody,
};
pub use errors::DirectE2eeError;
pub use helpers::message_service_did_from_document;
pub use models::{
    ApplicationPlaintext, DirectCipherBody, DirectEnvelopeMetadata, DirectInitBody,
    DirectSessionState, OneTimePrekey, PendingOutboundRecord, PrekeyBundle, RatchetHeader,
    SignedPrekey, SkippedMessageKey,
};
pub use ratchet::{decrypt_with_step, derive_chain_step, encrypt_with_step, ChainStep, MAX_SKIP};
pub use session::DirectE2eeSession;
pub use store::{IdentityKeyStore, PendingOutboundStore, SessionStore, SignedPrekeyStore};
pub use v2_aad::{build_init_aad_v2, build_message_aad_v2, canonical_application_plaintext_v2};
pub use v2_bundle::{
    build_prekey_bundle_v2, key_service_metadata_v2, signed_bundle_object_jcs_v2,
    verify_prekey_bundle_v2, V2GetPrekeyBundleBody, V2GetPrekeyBundleResult,
    V2PublishPrekeyBundleBody, V2PublishPrekeyBundleResult,
};
pub use v2_errors::{
    direct_e2ee_v2_error, DirectE2eeV2Error, DirectE2eeV2ProtocolError, DIRECT_E2EE_V2_ERRORS,
};
pub use v2_models::{
    V2ApplicationPlaintext, V2DirectBody, V2DirectCipherBody, V2DirectInitBody, V2DirectMetadata,
    V2KeyServiceMetadata, V2OneTimePrekey, V2PrekeyBundle, V2RatchetHeader, V2SignedPrekey,
    V2Target, CONTENT_TYPE_DIRECT_CIPHER_V2, CONTENT_TYPE_DIRECT_INIT_V2, DIRECT_E2EE_PROFILE_V2,
    DIRECT_E2EE_SECURITY_PROFILE, MTI_DIRECT_E2EE_SUITE_V2, TRANSPORT_PROTECTED_SECURITY_PROFILE,
};
pub use v2_session::{
    deserialize_pending_outbound_v2, deserialize_session_state_v2, disable_peer_device_sessions_v2,
    select_default_outbound_session_v2, serialize_pending_outbound_v2, serialize_session_state_v2,
    V2DirectE2eeSession, V2DirectSessionState, V2PendingOutboundRecord, V2SessionBinding,
    V2SkippedMessageKey, DIRECT_E2EE_V2_PENDING_STATE_FORMAT, DIRECT_E2EE_V2_SESSION_STATE_FORMAT,
    V2_SESSION_STATUS_ESTABLISHED, V2_SESSION_STATUS_PENDING_CONFIRMATION,
};
pub use v2_wire::{
    direct_send_request_v2, get_prekey_bundle_request_v2, parse_direct_send_request_v2,
    parse_direct_send_result_v2, parse_get_prekey_bundle_request_v2,
    parse_get_prekey_bundle_result_v2, parse_publish_prekey_bundle_request_v2,
    parse_publish_prekey_bundle_result_v2, publish_prekey_bundle_request_v2, V2DirectSendResult,
};
pub use x3dh::{
    derive_initial_material_for_initiator, derive_initial_material_for_responder,
    initial_secret_key_and_nonce, InitialMaterial,
};
