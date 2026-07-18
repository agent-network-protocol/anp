pub mod device_manifest;
pub mod did_resolver;
pub mod did_wba;
pub mod did_wba_authenticator;
pub mod did_wba_verifier;
pub mod federation;
pub mod http_signatures;
pub mod verification_methods;

pub use device_manifest::{
    add_device_to_did_document, build_vnext_did_document, find_eligible_device,
    parse_device_manifest, remove_device_from_did_document, update_device_in_did_document,
    validate_device_manifest, DeviceManifest, DeviceManifestEntry, DeviceManifestError,
    DEVICE_MANIFEST_TYPE, PROFILE_CORE_BINDING_V2, PROFILE_DIRECT_BASE_V2, PROFILE_DIRECT_E2EE_V2,
    PROFILE_GROUP_BASE_V2, PROFILE_GROUP_E2EE_V2, PROFILE_IDENTITY_DISCOVERY_V2,
};
pub use did_resolver::{
    resolve_did_document, resolve_did_document_sync, resolve_did_document_with_options,
};
#[allow(deprecated)]
pub use did_wba::{
    build_agent_message_service, build_agent_message_service_with_options,
    build_anp_message_service, build_group_message_service,
    build_group_message_service_with_options, compute_jwk_fingerprint,
    compute_multikey_fingerprint, create_did_wba_document,
    create_did_wba_document_with_creation_options, create_did_wba_document_with_key_binding,
    extract_auth_header_parts, find_verification_method, generate_auth_header, generate_auth_json,
    is_assertion_method_authorized, is_authentication_authorized, resolve_did_wba_document,
    resolve_did_wba_document_sync, resolve_did_wba_document_with_options,
    validate_did_document_binding, verify_auth_header_signature, verify_auth_json_signature,
    verify_did_key_binding, AnpMessageServiceOptions, AuthenticationError, DidDocumentBundle,
    DidDocumentCreationOptions, DidDocumentOptions, DidProfile, DidResolutionOptions,
    ParsedAuthHeader, ANP_MESSAGE_SERVICE_TYPE, VM_KEY_AUTH, VM_KEY_E2EE_AGREEMENT,
    VM_KEY_E2EE_SIGNING,
};
pub use did_wba_authenticator::{AuthMode, DIDWbaAuthHeader};
pub use did_wba_verifier::{
    DidWbaVerifier, DidWbaVerifierConfig, DidWbaVerifierError, VerificationSuccess,
};
pub use federation::{
    verify_federated_http_request, FederatedVerificationError, FederatedVerificationOptions,
    FederatedVerificationResult,
};
pub use http_signatures::{
    build_content_digest, extract_signature_metadata, generate_http_signature_headers,
    verify_content_digest, verify_http_message_signature, HttpSignatureError, HttpSignatureOptions,
    SignatureMetadata,
};
pub use verification_methods::{
    create_verification_method, extract_public_key, VerificationMethod, VerificationMethodError,
};
