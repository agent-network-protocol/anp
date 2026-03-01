"""基于 HPKE (RFC 9180) 的端到端加密模块。

协议规范：09-ANP-端到端即时消息协议规范.md
密码栈：DHKEM(X25519, HKDF-SHA256) / HKDF-SHA256 / AES-128-GCM
签名算法：ECDSA secp256r1 (P-256)
"""

from anp.e2e_encryption_hpke.crypto import decrypt_aes_128_gcm, encrypt_aes_128_gcm
from anp.e2e_encryption_hpke.group_session import GroupE2eeSession, SenderKeyState
from anp.e2e_encryption_hpke.hpke import hpke_open, hpke_seal
from anp.e2e_encryption_hpke.key_manager import HpkeKeyManager
from anp.e2e_encryption_hpke.key_pair import (
    extract_signing_public_key_from_did_document,
    extract_x25519_public_key_from_did_document,
    generate_x25519_key_pair,
    private_key_from_bytes,
    private_key_to_bytes,
    public_key_from_bytes,
    public_key_from_multibase,
    public_key_to_bytes,
    public_key_to_multibase,
)
from anp.e2e_encryption_hpke.message_builder import (
    build_e2ee_error,
    build_e2ee_init,
    build_e2ee_msg,
    build_e2ee_rekey,
    build_group_e2ee_key,
    build_group_e2ee_msg,
    build_group_epoch_advance,
)
from anp.e2e_encryption_hpke.message_parser import (
    detect_message_type,
    parse_e2ee_error,
    parse_e2ee_init,
    parse_e2ee_msg,
    parse_group_e2ee_key,
    parse_group_e2ee_msg,
    parse_group_epoch_advance,
)
from anp.e2e_encryption_hpke.models import (
    DEFAULT_EXPIRES,
    DEFAULT_MAX_SKIP,
    DEFAULT_SKIP_KEY_TTL,
    HPKE_SUITE,
    OLD_EPOCH_TTL,
    PROOF_TYPE,
    E2eeErrorContent,
    E2eeInitContent,
    E2eeMsgContent,
    EpochReason,
    ErrorCode,
    GroupE2eeKeyContent,
    GroupE2eeMsgContent,
    GroupEpochAdvanceContent,
    MessageType,
    Proof,
    SeqMode,
)
from anp.e2e_encryption_hpke.proof import generate_proof, verify_proof
from anp.e2e_encryption_hpke.ratchet import (
    assign_chain_keys,
    derive_chain_keys,
    derive_group_message_key,
    derive_message_key,
    determine_direction,
)
from anp.e2e_encryption_hpke.seq_manager import SeqManager
from anp.e2e_encryption_hpke.session import E2eeHpkeSession, SessionState

__all__ = [
    # session
    "E2eeHpkeSession",
    "SessionState",
    # group_session
    "GroupE2eeSession",
    "SenderKeyState",
    # key_manager
    "HpkeKeyManager",
    # models
    "HPKE_SUITE",
    "PROOF_TYPE",
    "DEFAULT_EXPIRES",
    "DEFAULT_MAX_SKIP",
    "DEFAULT_SKIP_KEY_TTL",
    "OLD_EPOCH_TTL",
    "MessageType",
    "ErrorCode",
    "EpochReason",
    "SeqMode",
    "Proof",
    "E2eeInitContent",
    "E2eeMsgContent",
    "E2eeErrorContent",
    "GroupE2eeKeyContent",
    "GroupE2eeMsgContent",
    "GroupEpochAdvanceContent",
    # hpke
    "hpke_seal",
    "hpke_open",
    # key_pair
    "generate_x25519_key_pair",
    "public_key_to_bytes",
    "public_key_from_bytes",
    "private_key_to_bytes",
    "private_key_from_bytes",
    "public_key_to_multibase",
    "public_key_from_multibase",
    "extract_x25519_public_key_from_did_document",
    "extract_signing_public_key_from_did_document",
    # ratchet
    "derive_chain_keys",
    "determine_direction",
    "assign_chain_keys",
    "derive_message_key",
    "derive_group_message_key",
    # crypto
    "encrypt_aes_128_gcm",
    "decrypt_aes_128_gcm",
    # seq_manager
    "SeqManager",
    # proof
    "generate_proof",
    "verify_proof",
    # message_builder
    "build_e2ee_init",
    "build_e2ee_msg",
    "build_e2ee_rekey",
    "build_e2ee_error",
    "build_group_e2ee_key",
    "build_group_e2ee_msg",
    "build_group_epoch_advance",
    # message_parser
    "detect_message_type",
    "parse_e2ee_init",
    "parse_e2ee_msg",
    "parse_e2ee_error",
    "parse_group_e2ee_key",
    "parse_group_e2ee_msg",
    "parse_group_epoch_advance",
]
