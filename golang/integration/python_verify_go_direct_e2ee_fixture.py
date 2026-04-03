import base64
import json
import sys
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)

from anp.direct_e2ee import DirectE2eeSession
from anp.direct_e2ee.models import (
    DirectCipherBody,
    DirectEnvelopeMetadata,
    DirectInitBody,
    RatchetHeader,
)


def b64u_decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def main(path: str) -> None:
    fixture = json.loads(Path(path).read_text(encoding="utf-8"))
    bob_static = X25519PrivateKey.from_private_bytes(
        b64u_decode(fixture["bob_static_private_key_b64u"])
    )
    bob_spk = X25519PrivateKey.from_private_bytes(
        b64u_decode(fixture["bob_signed_prekey_private_key_b64u"])
    )
    init_metadata = DirectEnvelopeMetadata(**fixture["init_metadata"])
    follow_up_metadata = DirectEnvelopeMetadata(**fixture["follow_up_metadata"])
    init_body = DirectInitBody(**fixture["init_body"])
    cipher_body = DirectCipherBody(
        session_id=fixture["cipher_body"]["session_id"],
        suite=fixture["cipher_body"]["suite"],
        ratchet_header=RatchetHeader(**fixture["cipher_body"]["ratchet_header"]),
        ciphertext_b64u=fixture["cipher_body"]["ciphertext_b64u"],
    )
    alice_key_id = init_body.sender_static_key_agreement_id
    alice_method = next(
        item
        for item in fixture["alice_did_document"]["verificationMethod"]
        if item["id"] == alice_key_id
    )
    alice_pub = base58_decode_multibase(alice_method["publicKeyMultibase"])
    session, plaintext = DirectE2eeSession.accept_incoming_init(
        init_metadata,
        fixture["bob_did_document"]["id"] + "#key-3",
        bob_static,
        bob_spk,
        X25519PublicKey.from_public_bytes(alice_pub),
        init_body,
    )
    follow_up = DirectE2eeSession.decrypt_follow_up(
        session,
        follow_up_metadata,
        cipher_body,
        "application/json",
    )
    print(json.dumps({"init_text": plaintext.text, "follow_up_payload": follow_up.payload}))


def base58_decode_multibase(value: str) -> bytes:
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    index = {char: i for i, char in enumerate(alphabet)}
    raw = value[1:] if value.startswith("z") else value
    number = 0
    for char in raw:
        number = number * 58 + index[char]
    data = number.to_bytes((number.bit_length() + 7) // 8, "big") if number else b""
    leading = 0
    for char in raw:
        if char != alphabet[0]:
            break
        leading += 1
    decoded = b"\x00" * leading + data
    if len(decoded) == 34 and decoded[:2] == b"\xec\x01":
        decoded = decoded[2:]
    return decoded


if __name__ == "__main__":
    main(sys.argv[1])
