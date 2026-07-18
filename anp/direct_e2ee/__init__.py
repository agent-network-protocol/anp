"""P5 direct E2EE helpers.

Unprefixed session APIs retain v1 semantics. Explicit ``V2`` models and
``*_v2`` builders expose the vNext wire contract without sharing v1 state.
"""

from .client import MessageServiceDirectE2eeClient
from .errors import DirectE2eeError
from .prekey_manager import PrekeyManager
from .session import DirectE2eeSession
from .store import FileSessionStore, FileSignedPrekeyStore
from .v2_aad import (
    build_init_aad_v2,
    build_message_aad_v2,
    canonical_application_plaintext_v2,
)
from .v2_bundle import (
    build_prekey_bundle_v2,
    key_service_metadata_v2,
    signed_bundle_object_jcs_v2,
    verify_prekey_bundle_v2,
)
from .v2_errors import DIRECT_E2EE_V2_ERRORS, DirectE2eeV2Error
from .v2_models import (
    V2ApplicationPlaintext,
    V2DirectCipherBody,
    V2DirectInitBody,
    V2DirectMetadata,
    V2KeyServiceMetadata,
    V2OneTimePrekey,
    V2PrekeyBundle,
    V2RatchetHeader,
    V2SignedPrekey,
    V2Target,
)
from .v2_wire import (
    V2DirectSendResult,
    V2GetPrekeyBundleResult,
    V2PublishPrekeyBundleResult,
    direct_send_request_v2,
    get_prekey_bundle_request_v2,
    parse_direct_send_request_v2,
    parse_direct_send_result_v2,
    parse_get_prekey_bundle_request_v2,
    parse_get_prekey_bundle_result_v2,
    parse_publish_prekey_bundle_request_v2,
    parse_publish_prekey_bundle_result_v2,
    publish_prekey_bundle_request_v2,
)

__all__ = [
    "DirectE2eeError",
    "DirectE2eeSession",
    "FileSessionStore",
    "FileSignedPrekeyStore",
    "MessageServiceDirectE2eeClient",
    "PrekeyManager",
    "DIRECT_E2EE_V2_ERRORS",
    "DirectE2eeV2Error",
    "V2ApplicationPlaintext",
    "V2DirectCipherBody",
    "V2DirectInitBody",
    "V2DirectMetadata",
    "V2DirectSendResult",
    "V2GetPrekeyBundleResult",
    "V2KeyServiceMetadata",
    "V2OneTimePrekey",
    "V2PrekeyBundle",
    "V2PublishPrekeyBundleResult",
    "V2RatchetHeader",
    "V2SignedPrekey",
    "V2Target",
    "build_init_aad_v2",
    "build_message_aad_v2",
    "build_prekey_bundle_v2",
    "canonical_application_plaintext_v2",
    "direct_send_request_v2",
    "get_prekey_bundle_request_v2",
    "key_service_metadata_v2",
    "parse_direct_send_request_v2",
    "parse_direct_send_result_v2",
    "parse_get_prekey_bundle_request_v2",
    "parse_get_prekey_bundle_result_v2",
    "parse_publish_prekey_bundle_request_v2",
    "parse_publish_prekey_bundle_result_v2",
    "publish_prekey_bundle_request_v2",
    "signed_bundle_object_jcs_v2",
    "verify_prekey_bundle_v2",
]
