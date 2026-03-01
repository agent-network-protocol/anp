from .did_wba import (
    VM_KEY_AUTH,
    VM_KEY_E2EE_AGREEMENT,
    VM_KEY_E2EE_SIGNING,
    compute_jwk_fingerprint,
    create_did_wba_document,
    create_did_wba_document_with_key_binding,
    extract_auth_header_parts,
    generate_auth_header,
    generate_auth_json,
    resolve_did_wba_document,
    resolve_did_wba_document_sync,
    verify_auth_header_signature,
    verify_auth_json_signature,
    verify_did_key_binding,
)
from .did_wba_authenticator import DIDWbaAuthHeader
from .did_wba_verifier import DidWbaVerifier, DidWbaVerifierConfig, DidWbaVerifierError

# Define what should be exported when using "from anp.authentication import *"
__all__ = ['VM_KEY_AUTH', \
           'VM_KEY_E2EE_SIGNING', \
           'VM_KEY_E2EE_AGREEMENT', \
           'compute_jwk_fingerprint', \
           'create_did_wba_document', \
           'create_did_wba_document_with_key_binding', \
           'resolve_did_wba_document', \
           'resolve_did_wba_document_sync', \
           'generate_auth_header', \
           'generate_auth_json', \
           'verify_auth_header_signature', \
           'verify_auth_json_signature', \
           'verify_did_key_binding', \
           'extract_auth_header_parts', \
           'DIDWbaAuthHeader', \
           'DidWbaVerifier', \
           'DidWbaVerifierConfig', \
           'DidWbaVerifierError'
           ]

