pub mod binding;
pub mod errors;
pub mod models;
pub mod resolver;
pub mod validator;

pub use binding::{
    build_handle_service_entry, extract_handle_service_from_did_document, verify_handle_binding,
    verify_handle_binding_with_options, BindingVerificationOptions, BindingVerificationResult,
};
pub use errors::{
    HandleBindingError, HandleGoneError, HandleMovedError, HandleNotFoundError,
    HandleResolutionError, HandleValidationError, WbaUriParseError, WnsError,
};
pub use models::{HandleResolutionDocument, HandleServiceEntry, HandleStatus, ParsedWbaUri};
pub use resolver::{
    resolve_handle, resolve_handle_from_uri, resolve_handle_sync, resolve_handle_with_options,
    ResolveHandleOptions,
};
pub use validator::{
    build_resolution_url, build_wba_uri, normalize_handle, parse_wba_uri, validate_handle,
    validate_local_part,
};
