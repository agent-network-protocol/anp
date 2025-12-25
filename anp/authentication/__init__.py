from .did_wba import (
    create_did_wba_document,
    extract_auth_header_parts,
    generate_auth_header,
    generate_auth_json,
    resolve_did_wba_document,
    resolve_did_wba_document_sync,
    verify_auth_header_signature,
    verify_auth_json_signature,
)
from .did_wba_authenticator import DIDWbaAuthHeader
from .did_wba_verifier import DidWbaVerifier, DidWbaVerifierConfig, DidWbaVerifierError

# Define what should be exported when using "from anp.authentication import *"
__all__ = ['create_did_wba_document', \
           'resolve_did_wba_document', \
           'resolve_did_wba_document_sync', \
           'generate_auth_header', \
           'generate_auth_json', \
           'verify_auth_header_signature', \
           'verify_auth_json_signature', \
           'extract_auth_header_parts', \
           'DIDWbaAuthHeader', \
           'DidWbaVerifier', \
           'DidWbaVerifierConfig', \
           'DidWbaVerifierError'
           ]

