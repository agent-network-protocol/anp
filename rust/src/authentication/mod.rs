pub mod did_wba;
pub mod did_wba_authenticator;
pub mod did_wba_verifier;
pub mod http_signatures;
pub mod verification_methods;

pub use did_wba::{
    create_did_wba_document,
    create_did_wba_document_with_key_binding,
    extract_auth_header_parts,
    find_verification_method,
    generate_auth_header,
    generate_auth_json,
    resolve_did_wba_document,
    resolve_did_wba_document_sync,
    resolve_did_wba_document_with_options,
    validate_did_document_binding,
    verify_auth_header_signature,
    verify_auth_json_signature,
    verify_did_key_binding,
    AuthenticationError,
    DidDocumentBundle,
    DidDocumentOptions,
    DidProfile,
    DidResolutionOptions,
    ParsedAuthHeader,
    VM_KEY_AUTH,
    VM_KEY_E2EE_AGREEMENT,
    VM_KEY_E2EE_SIGNING,
    compute_jwk_fingerprint,
    compute_multikey_fingerprint,
};
pub use did_wba_authenticator::{AuthMode, DIDWbaAuthHeader};
pub use did_wba_verifier::{
    DidWbaVerifier,
    DidWbaVerifierConfig,
    DidWbaVerifierError,
    VerificationSuccess,
};
pub use http_signatures::{
    build_content_digest,
    extract_signature_metadata,
    generate_http_signature_headers,
    verify_content_digest,
    verify_http_message_signature,
    HttpSignatureError,
    HttpSignatureOptions,
    SignatureMetadata,
};
pub use verification_methods::{
    create_verification_method,
    extract_public_key,
    VerificationMethod,
    VerificationMethodError,
};
