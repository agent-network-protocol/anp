"""Typed ANP vNext Device Manifest parsing, validation, and DID helpers.

[INPUT]: Public DID document JSON, typed public device entries, and explicit
root/device public verification methods.
[OUTPUT]: Validated Manifest models and unsigned build/add/update/remove DID
document copies with synchronized verification relationships.
[POS]: Public P2 vNext identity/discovery SDK surface; it never owns private
key generation, root signing, or AWiki-local device management state.
"""

import base64
import copy
import math
import re
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Tuple

import base58
from cryptography.hazmat.primitives.asymmetric import ec


DEVICE_MANIFEST_TYPE = "ANPDeviceManifest"

PROFILE_CORE_BINDING_V2 = "anp.core.binding.v2"
PROFILE_IDENTITY_DISCOVERY_V2 = "anp.identity.discovery.v2"
PROFILE_DIRECT_BASE_V2 = "anp.direct.base.v2"
PROFILE_GROUP_BASE_V2 = "anp.group.base.v2"
PROFILE_DIRECT_E2EE_V2 = "anp.direct.e2ee.v2"
PROFILE_GROUP_E2EE_V2 = "anp.group.e2ee.v2"

_MANIFEST_FIELDS = frozenset({"type", "devices"})
_ENTRY_FIELDS = frozenset({"device_id", "signing_key_id", "e2ee_key_id", "profiles"})
_P5_DEPENDENCIES = frozenset(
    {
        PROFILE_CORE_BINDING_V2,
        PROFILE_IDENTITY_DISCOVERY_V2,
        PROFILE_DIRECT_BASE_V2,
        PROFILE_DIRECT_E2EE_V2,
    }
)
_P6_DEPENDENCIES = frozenset(
    {
        PROFILE_CORE_BINDING_V2,
        PROFILE_IDENTITY_DISCOVERY_V2,
        PROFILE_GROUP_BASE_V2,
        PROFILE_GROUP_E2EE_V2,
    }
)
_BASE64URL_RE = re.compile(r"^[A-Za-z0-9_-]+$")
_SIGNING_ALGORITHMS = frozenset({"Ed25519", "P-256", "secp256k1"})


class DeviceManifestError(ValueError):
    """Raised when a Device Manifest violates the vNext contract."""


@dataclass(frozen=True)
class DeviceManifestEntry:
    """One public cryptographic device endpoint in a Device Manifest."""

    device_id: str
    signing_key_id: str
    e2ee_key_id: str
    profiles: Tuple[str, ...]

    def to_dict(self) -> Dict[str, Any]:
        """Serialize the closed standard device entry."""
        return {
            "device_id": self.device_id,
            "signing_key_id": self.signing_key_id,
            "e2ee_key_id": self.e2ee_key_id,
            "profiles": list(self.profiles),
        }


@dataclass(frozen=True)
class DeviceManifest:
    """The typed value of the DID document ``deviceManifest`` extension."""

    type: str
    devices: Tuple[DeviceManifestEntry, ...]

    def to_dict(self) -> Dict[str, Any]:
        """Serialize only the Device Manifest, not the containing DID document."""
        return {
            "type": self.type,
            "devices": [device.to_dict() for device in self.devices],
        }


@dataclass(frozen=True)
class _PublicKeyIdentity:
    algorithm: str
    raw_public_key: bytes


def parse_device_manifest(
    did_document: Dict[str, Any],
) -> Optional[DeviceManifest]:
    """Parse the optional closed Device Manifest schema.

    Unknown members elsewhere in ``did_document`` are neither interpreted nor
    removed. A missing extension is valid for DIDs that only support Base
    Profiles and returns ``None``.
    """
    if "deviceManifest" not in did_document:
        return None

    raw_manifest = did_document["deviceManifest"]
    if not isinstance(raw_manifest, dict):
        raise DeviceManifestError("deviceManifest must be an object")
    _require_exact_fields(raw_manifest, _MANIFEST_FIELDS, "deviceManifest")
    if raw_manifest["type"] != DEVICE_MANIFEST_TYPE:
        raise DeviceManifestError("deviceManifest.type must equal ANPDeviceManifest")

    raw_devices = raw_manifest["devices"]
    if not isinstance(raw_devices, list):
        raise DeviceManifestError("deviceManifest.devices must be an array")

    devices: List[DeviceManifestEntry] = []
    for index, raw_entry in enumerate(raw_devices):
        subject = "deviceManifest.devices[{}]".format(index)
        if not isinstance(raw_entry, dict):
            raise DeviceManifestError("{} must be an object".format(subject))
        _require_exact_fields(raw_entry, _ENTRY_FIELDS, subject)

        device_id = _require_string(
            raw_entry["device_id"], "{}.device_id".format(subject)
        )
        signing_key_id = _require_string(
            raw_entry["signing_key_id"],
            "{}.signing_key_id".format(subject),
        )
        e2ee_key_id = _require_string(
            raw_entry["e2ee_key_id"], "{}.e2ee_key_id".format(subject)
        )
        raw_profiles = raw_entry["profiles"]
        if not isinstance(raw_profiles, list):
            raise DeviceManifestError(
                "{}.profiles must be a string array".format(subject)
            )
        profiles = tuple(
            _require_string(profile, "{}.profiles[]".format(subject))
            for profile in raw_profiles
        )
        devices.append(
            DeviceManifestEntry(
                device_id=device_id,
                signing_key_id=signing_key_id,
                e2ee_key_id=e2ee_key_id,
                profiles=profiles,
            )
        )

    return DeviceManifest(type=DEVICE_MANIFEST_TYPE, devices=tuple(devices))


def validate_device_manifest(
    did_document: Dict[str, Any],
) -> Optional[DeviceManifest]:
    """Parse and validate Manifest references, relationships, and dependencies."""
    manifest = parse_device_manifest(did_document)
    if manifest is None:
        return None

    did = _require_non_empty_string(did_document.get("id"), "DID document id")
    verification_methods = did_document.get("verificationMethod")
    if not isinstance(verification_methods, list):
        raise DeviceManifestError("DID document verificationMethod must be an array")

    methods_by_id: Dict[str, List[Dict[str, Any]]] = {}
    for method in verification_methods:
        if not isinstance(method, dict):
            continue
        method_id = method.get("id")
        if isinstance(method_id, str):
            methods_by_id.setdefault(method_id, []).append(method)

    seen_device_ids = set()
    seen_key_ids = set()
    for entry in manifest.devices:
        _require_non_empty_string(entry.device_id, "device_id")
        _require_non_empty_string(entry.signing_key_id, "signing_key_id")
        _require_non_empty_string(entry.e2ee_key_id, "e2ee_key_id")
        if not entry.profiles:
            raise DeviceManifestError("profiles must be non-empty")
        for profile in entry.profiles:
            _require_non_empty_string(profile, "profile")
        if entry.device_id in seen_device_ids:
            raise DeviceManifestError("device_id must be unique")
        seen_device_ids.add(entry.device_id)

        if entry.signing_key_id == entry.e2ee_key_id:
            raise DeviceManifestError("signing_key_id and e2ee_key_id must be distinct")
        for key_id in (entry.signing_key_id, entry.e2ee_key_id):
            if key_id in seen_key_ids:
                raise DeviceManifestError(
                    "a verification method can belong to only one device entry"
                )
            seen_key_ids.add(key_id)
            _validate_same_document_method(did, key_id, methods_by_id)

        profile_set = set(entry.profiles)
        if PROFILE_DIRECT_E2EE_V2 in profile_set:
            _require_dependencies(profile_set, _P5_DEPENDENCIES, "P5")
            _require_relationship(
                did_document,
                "assertionMethod",
                entry.signing_key_id,
                "P5 signing key",
            )
        if PROFILE_GROUP_E2EE_V2 in profile_set:
            _require_dependencies(profile_set, _P6_DEPENDENCIES, "P6")
            _require_relationship(
                did_document,
                "assertionMethod",
                entry.signing_key_id,
                "P6 binding key",
            )
            _require_relationship(
                did_document,
                "authentication",
                entry.signing_key_id,
                "P6 origin-proof key",
            )
        _require_relationship(
            did_document,
            "keyAgreement",
            entry.e2ee_key_id,
            "device E2EE key",
        )

    return manifest


def find_eligible_device(
    did_document: Dict[str, Any],
    device_id: str,
    required_profile: str,
) -> Optional[DeviceManifestEntry]:
    """Return a validated device that declares ``required_profile``."""
    manifest = validate_device_manifest(did_document)
    if manifest is None:
        return None
    if required_profile not in {
        PROFILE_DIRECT_E2EE_V2,
        PROFILE_GROUP_E2EE_V2,
    }:
        return None
    for entry in manifest.devices:
        if entry.device_id == device_id and required_profile in entry.profiles:
            return entry
    return None


def build_vnext_did_document(
    base_document: Dict[str, Any],
    root_key_id: str,
    root_verification_method: Dict[str, Any],
    device: DeviceManifestEntry,
    device_signing_verification_method: Dict[str, Any],
    device_e2ee_verification_method: Dict[str, Any],
) -> Dict[str, Any]:
    """Build an unsigned vNext DID document from public key material only.

    ``base_document`` may contain ordinary DID members and extensions, but the
    relationships managed by this helper must not already be present. The
    caller must root-sign the returned document before publishing it.
    """
    document = _clone_document(base_document)
    for field in (
        "verificationMethod",
        "authentication",
        "assertionMethod",
        "keyAgreement",
        "deviceManifest",
        "proof",
    ):
        if field in document:
            raise DeviceManifestError(
                "base DID document must not contain managed field {}".format(field)
            )

    did = _document_did(document)
    _validate_root_method(did, root_key_id, root_verification_method)
    _validate_device_methods(
        did,
        root_key_id,
        device,
        device_signing_verification_method,
        device_e2ee_verification_method,
    )
    document.update(
        {
            "verificationMethod": [
                copy.deepcopy(root_verification_method),
                copy.deepcopy(device_signing_verification_method),
                copy.deepcopy(device_e2ee_verification_method),
            ],
            "authentication": [device.signing_key_id],
            "assertionMethod": [root_key_id, device.signing_key_id],
            "keyAgreement": [device.e2ee_key_id],
            "deviceManifest": {
                "type": DEVICE_MANIFEST_TYPE,
                "devices": [device.to_dict()],
            },
        }
    )
    _validate_vnext_document(document, root_key_id)
    return document


def add_device_to_did_document(
    did_document: Dict[str, Any],
    root_key_id: str,
    device: DeviceManifestEntry,
    device_signing_verification_method: Dict[str, Any],
    device_e2ee_verification_method: Dict[str, Any],
    retired_device_ids: Iterable[str],
) -> Dict[str, Any]:
    """Add one never-before-used device ID and return an unsigned copy."""
    document = _prepare_document_for_mutation(did_document, root_key_id)
    manifest = validate_device_manifest(document)
    if manifest is None:
        raise DeviceManifestError("deviceManifest is required for device update")
    if any(entry.device_id == device.device_id for entry in manifest.devices):
        raise DeviceManifestError("device_id already exists")
    retired = _validate_retired_device_ids(retired_device_ids)
    if device.device_id in retired:
        raise DeviceManifestError("retired device_id cannot be reused")
    _append_device_material(
        document,
        root_key_id,
        device,
        device_signing_verification_method,
        device_e2ee_verification_method,
    )
    _validate_vnext_document(document, root_key_id)
    return document


def update_device_in_did_document(
    did_document: Dict[str, Any],
    root_key_id: str,
    device: DeviceManifestEntry,
    device_signing_verification_method: Dict[str, Any],
    device_e2ee_verification_method: Dict[str, Any],
) -> Dict[str, Any]:
    """Replace one device's public keys/Profile entry in an unsigned copy."""
    document = _prepare_document_for_mutation(did_document, root_key_id)
    manifest = validate_device_manifest(document)
    if manifest is None:
        raise DeviceManifestError("deviceManifest is required for device update")
    old_entry = next(
        (entry for entry in manifest.devices if entry.device_id == device.device_id),
        None,
    )
    if old_entry is None:
        raise DeviceManifestError("device_id does not exist")

    _remove_device_material(document, old_entry)
    _append_device_material(
        document,
        root_key_id,
        device,
        device_signing_verification_method,
        device_e2ee_verification_method,
    )
    _validate_vnext_document(document, root_key_id)
    return document


def remove_device_from_did_document(
    did_document: Dict[str, Any],
    root_key_id: str,
    device_id: str,
) -> Dict[str, Any]:
    """Remove one device and its active key references from an unsigned copy."""
    document = _prepare_document_for_mutation(did_document, root_key_id)
    manifest = validate_device_manifest(document)
    if manifest is None:
        raise DeviceManifestError("deviceManifest is required for device update")
    old_entry = next(
        (entry for entry in manifest.devices if entry.device_id == device_id),
        None,
    )
    if old_entry is None:
        raise DeviceManifestError("device_id does not exist")

    _remove_device_material(document, old_entry)
    _validate_vnext_document(document, root_key_id)
    return document


def _clone_document(did_document: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(did_document, dict):
        raise DeviceManifestError("DID document must be an object")
    _validate_json_value(did_document, "DID document")
    return copy.deepcopy(did_document)


def _document_did(did_document: Dict[str, Any]) -> str:
    return _require_non_empty_string(did_document.get("id"), "DID document id")


def _prepare_document_for_mutation(
    did_document: Dict[str, Any], root_key_id: str
) -> Dict[str, Any]:
    document = _clone_document(did_document)
    _validate_vnext_document(document, root_key_id)
    # A mutation invalidates any existing root proof. Returning it would make a
    # stale signature look publishable, so callers must explicitly sign again.
    document.pop("proof", None)
    return document


def _validate_vnext_document(did_document: Dict[str, Any], root_key_id: str) -> None:
    _validate_json_value(did_document, "DID document")
    _reject_private_key_material(did_document, "DID document")
    did = _document_did(did_document)
    methods = did_document.get("verificationMethod")
    if not isinstance(methods, list):
        raise DeviceManifestError("DID document verificationMethod must be an array")
    root_methods = [
        method
        for method in methods
        if isinstance(method, dict) and method.get("id") == root_key_id
    ]
    if len(root_methods) != 1:
        raise DeviceManifestError(
            "root key must resolve exactly once in verificationMethod"
        )
    root_identity = _validate_root_method(did, root_key_id, root_methods[0])
    _require_relationship(
        did_document,
        "assertionMethod",
        root_key_id,
        "DID root key",
    )
    manifest = validate_device_manifest(did_document)
    if manifest is None:
        raise DeviceManifestError("deviceManifest is required")
    seen_material = {root_identity.raw_public_key}
    for entry in manifest.devices:
        if root_key_id in (entry.signing_key_id, entry.e2ee_key_id):
            raise DeviceManifestError("DID root key cannot be a device key")
        signing_method = _unique_method(did_document, entry.signing_key_id)
        e2ee_method = _unique_method(did_document, entry.e2ee_key_id)
        signing_identity, e2ee_identity = _validate_device_methods(
            did,
            root_key_id,
            entry,
            signing_method,
            e2ee_method,
        )
        _require_relationship(
            did_document,
            "authentication",
            entry.signing_key_id,
            "device signing key",
        )
        _require_relationship(
            did_document,
            "assertionMethod",
            entry.signing_key_id,
            "device signing key",
        )
        _require_relationship(
            did_document,
            "keyAgreement",
            entry.e2ee_key_id,
            "device E2EE key",
        )
        if _relationship_contains(did_document, "keyAgreement", entry.signing_key_id):
            raise DeviceManifestError("device signing key must not be in keyAgreement")
        if _relationship_contains(
            did_document, "authentication", entry.e2ee_key_id
        ) or _relationship_contains(did_document, "assertionMethod", entry.e2ee_key_id):
            raise DeviceManifestError(
                "device E2EE key must not be a signing relationship"
            )
        for identity in (signing_identity, e2ee_identity):
            if identity.raw_public_key in seen_material:
                raise DeviceManifestError(
                    "root and device public key material must be unique"
                )
            seen_material.add(identity.raw_public_key)


def _validate_root_method(
    did: str,
    root_key_id: str,
    verification_method: Dict[str, Any],
) -> _PublicKeyIdentity:
    return _validate_public_method(
        did,
        root_key_id,
        verification_method,
        allowed_algorithms=_SIGNING_ALGORITHMS,
        subject="DID root verification method",
    )


def _validate_device_methods(
    did: str,
    root_key_id: str,
    device: DeviceManifestEntry,
    signing_method: Dict[str, Any],
    e2ee_method: Dict[str, Any],
) -> Tuple[_PublicKeyIdentity, _PublicKeyIdentity]:
    if root_key_id in (device.signing_key_id, device.e2ee_key_id):
        raise DeviceManifestError("DID root key cannot be a device key")
    standard_object_proof = any(
        profile in {PROFILE_DIRECT_E2EE_V2, PROFILE_GROUP_E2EE_V2}
        for profile in device.profiles
    )
    signing_identity = _validate_public_method(
        did,
        device.signing_key_id,
        signing_method,
        allowed_algorithms=(
            frozenset({"Ed25519"}) if standard_object_proof else _SIGNING_ALGORITHMS
        ),
        subject="device signing verification method",
    )
    e2ee_identity = _validate_public_method(
        did,
        device.e2ee_key_id,
        e2ee_method,
        allowed_algorithms=frozenset({"X25519"}),
        subject="device E2EE verification method",
    )
    if signing_identity.raw_public_key == e2ee_identity.raw_public_key:
        raise DeviceManifestError("device key material must be unique across roles")
    return signing_identity, e2ee_identity


def _validate_public_method(
    did: str,
    expected_key_id: str,
    method: Dict[str, Any],
    *,
    allowed_algorithms: frozenset,
    subject: str,
) -> _PublicKeyIdentity:
    if not isinstance(method, dict):
        raise DeviceManifestError("{} must be an object".format(subject))
    _validate_json_value(method, subject)
    if method.get("id") != expected_key_id:
        raise DeviceManifestError("{} id does not match its role".format(subject))
    if method.get("controller") != did:
        raise DeviceManifestError("{} controller must match the DID".format(subject))
    _validate_same_document_key_id(did, expected_key_id)
    _reject_private_key_material(method, subject)
    method_type = _require_non_empty_string(
        method.get("type"), "{}.type".format(subject)
    )
    material_fields = [
        field
        for field in ("publicKeyJwk", "publicKeyMultibase", "publicKeyBase58")
        if field in method
    ]
    if len(material_fields) != 1:
        raise DeviceManifestError(
            "{} must contain exactly one supported public key field".format(subject)
        )
    material_field = material_fields[0]
    if material_field == "publicKeyJwk":
        identity = _decode_public_jwk(method_type, method[material_field], subject)
    elif material_field == "publicKeyMultibase":
        identity = _decode_public_multikey(method_type, method[material_field], subject)
    else:
        raise DeviceManifestError(
            "{} publicKeyBase58 is not supported by vNext helpers".format(subject)
        )
    if identity.algorithm not in allowed_algorithms:
        raise DeviceManifestError("{} uses the wrong key algorithm".format(subject))
    return identity


def _validate_same_document_key_id(did: str, key_id: str) -> None:
    if not key_id.startswith(did + "#") or key_id == did + "#":
        raise DeviceManifestError("key id must be a DID URL in the same document")


def _decode_public_jwk(
    method_type: str, value: Any, subject: str
) -> _PublicKeyIdentity:
    if method_type not in {
        "JsonWebKey2020",
        "EcdsaSecp256k1VerificationKey2019",
        "EcdsaSecp256r1VerificationKey2019",
    }:
        raise DeviceManifestError(
            "{} type is incompatible with publicKeyJwk".format(subject)
        )
    if not isinstance(value, dict):
        raise DeviceManifestError("{}.publicKeyJwk must be an object".format(subject))
    kty = value.get("kty")
    curve = value.get("crv")
    if kty == "OKP" and curve in {"Ed25519", "X25519"}:
        if method_type != "JsonWebKey2020":
            raise DeviceManifestError("{} type contradicts its JWK".format(subject))
        raw = _decode_canonical_base64url_32(value.get("x"), subject + ".x")
        return _PublicKeyIdentity(algorithm=curve, raw_public_key=raw)
    if kty == "EC" and curve in {"P-256", "secp256k1"}:
        expected_type = {
            "P-256": "EcdsaSecp256r1VerificationKey2019",
            "secp256k1": "EcdsaSecp256k1VerificationKey2019",
        }[curve]
        if method_type not in {"JsonWebKey2020", expected_type}:
            raise DeviceManifestError("{} type contradicts its JWK".format(subject))
        x = _decode_canonical_base64url_32(value.get("x"), subject + ".x")
        y = _decode_canonical_base64url_32(value.get("y"), subject + ".y")
        curve_impl = ec.SECP256R1() if curve == "P-256" else ec.SECP256K1()
        try:
            ec.EllipticCurvePublicNumbers(
                int.from_bytes(x, "big"), int.from_bytes(y, "big"), curve_impl
            ).public_key()
        except ValueError as error:
            raise DeviceManifestError(
                "{} contains an invalid EC point".format(subject)
            ) from error
        return _PublicKeyIdentity(algorithm=curve, raw_public_key=x + y)
    raise DeviceManifestError("{} contains an unsupported public JWK".format(subject))


def _decode_public_multikey(
    method_type: str, value: Any, subject: str
) -> _PublicKeyIdentity:
    if method_type not in {"Multikey", "X25519KeyAgreementKey2019"}:
        raise DeviceManifestError(
            "{} type is incompatible with publicKeyMultibase".format(subject)
        )
    if not isinstance(value, str) or not value.startswith("z") or len(value) == 1:
        raise DeviceManifestError(
            "{}.publicKeyMultibase must be base58btc".format(subject)
        )
    try:
        decoded = base58.b58decode(value[1:])
    except ValueError as error:
        raise DeviceManifestError(
            "{}.publicKeyMultibase is invalid".format(subject)
        ) from error
    if "z" + base58.b58encode(decoded).decode("ascii") != value:
        raise DeviceManifestError(
            "{}.publicKeyMultibase must be canonical".format(subject)
        )
    if len(decoded) != 34:
        raise DeviceManifestError(
            "{}.publicKeyMultibase must contain a 32-byte key".format(subject)
        )
    prefix = decoded[:2]
    if prefix == b"\xed\x01":
        algorithm = "Ed25519"
    elif prefix == b"\xec\x01":
        algorithm = "X25519"
    else:
        raise DeviceManifestError(
            "{}.publicKeyMultibase uses an unsupported codec".format(subject)
        )
    if method_type == "X25519KeyAgreementKey2019" and algorithm != "X25519":
        raise DeviceManifestError("{} type contradicts its Multikey".format(subject))
    return _PublicKeyIdentity(algorithm=algorithm, raw_public_key=decoded[2:])


def _decode_canonical_base64url_32(value: Any, subject: str) -> bytes:
    if not isinstance(value, str) or not _BASE64URL_RE.fullmatch(value):
        raise DeviceManifestError("{} must be unpadded base64url".format(subject))
    try:
        decoded = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (ValueError, TypeError) as error:
        raise DeviceManifestError("{} is invalid base64url".format(subject)) from error
    canonical = base64.urlsafe_b64encode(decoded).rstrip(b"=").decode("ascii")
    if len(decoded) != 32 or canonical != value:
        raise DeviceManifestError("{} must canonically encode 32 bytes".format(subject))
    return decoded


def _reject_private_key_material(value: Any, subject: str) -> None:
    if isinstance(value, dict):
        for key, nested in value.items():
            normalized_key = key.lower().replace("_", "").replace("-", "")
            if "privatekey" in normalized_key or (key == "d" and "kty" in value):
                raise DeviceManifestError(
                    "{} must not contain private key material".format(subject)
                )
            _reject_private_key_material(nested, subject)
    elif isinstance(value, list):
        for nested in value:
            _reject_private_key_material(nested, subject)


def _validate_json_value(value: Any, subject: str) -> None:
    if value is None or isinstance(value, (str, bool, int)):
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            raise DeviceManifestError("{} contains a non-finite number".format(subject))
        return
    if isinstance(value, list):
        for nested in value:
            _validate_json_value(nested, subject)
        return
    if isinstance(value, dict):
        for key, nested in value.items():
            if not isinstance(key, str):
                raise DeviceManifestError(
                    "{} contains a non-string object key".format(subject)
                )
            _validate_json_value(nested, subject)
        return
    raise DeviceManifestError("{} contains a non-JSON value".format(subject))


def _validate_retired_device_ids(retired_device_ids: Iterable[str]) -> set:
    if isinstance(retired_device_ids, (str, bytes)):
        raise DeviceManifestError("retired_device_ids must be a string collection")
    try:
        values = list(retired_device_ids)
    except TypeError as error:
        raise DeviceManifestError(
            "retired_device_ids must be a string collection"
        ) from error
    for device_id in values:
        _require_non_empty_string(device_id, "retired device_id")
    return set(values)


def _unique_method(did_document: Dict[str, Any], key_id: str) -> Dict[str, Any]:
    methods = did_document.get("verificationMethod")
    if not isinstance(methods, list):
        raise DeviceManifestError("DID document verificationMethod must be an array")
    matches = [
        method
        for method in methods
        if isinstance(method, dict) and method.get("id") == key_id
    ]
    if len(matches) != 1:
        raise DeviceManifestError(
            "key id must resolve exactly once in verificationMethod"
        )
    return matches[0]


def _append_device_material(
    document: Dict[str, Any],
    root_key_id: str,
    device: DeviceManifestEntry,
    signing_method: Dict[str, Any],
    e2ee_method: Dict[str, Any],
) -> None:
    did = _document_did(document)
    _validate_device_methods(did, root_key_id, device, signing_method, e2ee_method)
    methods = document.get("verificationMethod")
    authentication = document.get("authentication")
    assertion_method = document.get("assertionMethod")
    key_agreement = document.get("keyAgreement")
    manifest = document.get("deviceManifest")
    if (
        not all(
            isinstance(entries, list)
            for entries in (
                methods,
                authentication,
                assertion_method,
                key_agreement,
            )
        )
        or not isinstance(manifest, dict)
        or not isinstance(manifest.get("devices"), list)
    ):
        raise DeviceManifestError("DID document relationships are invalid")
    methods.extend([copy.deepcopy(signing_method), copy.deepcopy(e2ee_method)])
    authentication.append(device.signing_key_id)
    assertion_method.append(device.signing_key_id)
    key_agreement.append(device.e2ee_key_id)
    manifest["devices"].append(device.to_dict())


def _remove_device_material(
    document: Dict[str, Any], device: DeviceManifestEntry
) -> None:
    key_ids = {device.signing_key_id, device.e2ee_key_id}
    methods = document.get("verificationMethod")
    if not isinstance(methods, list):
        raise DeviceManifestError("DID document verificationMethod must be an array")
    document["verificationMethod"] = [
        method
        for method in methods
        if not (isinstance(method, dict) and method.get("id") in key_ids)
    ]
    for relationship in ("authentication", "assertionMethod", "keyAgreement"):
        entries = document.get(relationship)
        if not isinstance(entries, list):
            raise DeviceManifestError("{} must be an array".format(relationship))
        document[relationship] = [
            entry
            for entry in entries
            if not any(_relationship_entry_is(entry, key_id) for key_id in key_ids)
        ]
    manifest = document.get("deviceManifest")
    if not isinstance(manifest, dict) or not isinstance(manifest.get("devices"), list):
        raise DeviceManifestError("deviceManifest.devices must be an array")
    manifest["devices"] = [
        entry
        for entry in manifest["devices"]
        if not (isinstance(entry, dict) and entry.get("device_id") == device.device_id)
    ]


def _relationship_entry_is(entry: Any, key_id: str) -> bool:
    return entry == key_id or (isinstance(entry, dict) and entry.get("id") == key_id)


def _relationship_contains(
    did_document: Dict[str, Any], relationship: str, key_id: str
) -> bool:
    entries = did_document.get(relationship)
    return isinstance(entries, list) and any(
        _relationship_entry_is(entry, key_id) for entry in entries
    )


def _require_exact_fields(
    value: Dict[str, Any], expected: frozenset, subject: str
) -> None:
    if set(value) != expected:
        raise DeviceManifestError(
            "{} must contain exactly {}".format(subject, ", ".join(sorted(expected)))
        )


def _require_string(value: Any, subject: str) -> str:
    if not isinstance(value, str):
        raise DeviceManifestError("{} must be a string".format(subject))
    return value


def _require_non_empty_string(value: Any, subject: str) -> str:
    result = _require_string(value, subject)
    if not result:
        raise DeviceManifestError("{} must be a non-empty string".format(subject))
    return result


def _validate_same_document_method(
    did: str,
    key_id: str,
    methods_by_id: Dict[str, List[Dict[str, Any]]],
) -> None:
    if not key_id.startswith(did + "#") or key_id == did + "#":
        raise DeviceManifestError(
            "device key IDs must be DID URLs in the same DID document"
        )
    methods = methods_by_id.get(key_id, [])
    if len(methods) != 1:
        raise DeviceManifestError(
            "device key ID must resolve exactly once in verificationMethod"
        )


def _require_dependencies(
    profiles: set, required: frozenset, profile_name: str
) -> None:
    if not required.issubset(profiles):
        raise DeviceManifestError(
            "{} device profile dependencies are incomplete".format(profile_name)
        )


def _require_relationship(
    did_document: Dict[str, Any],
    relationship: str,
    key_id: str,
    subject: str,
) -> None:
    entries = did_document.get(relationship)
    if not isinstance(entries, list):
        raise DeviceManifestError("{} requires {}".format(subject, relationship))
    for entry in entries:
        if entry == key_id:
            return
        if isinstance(entry, dict) and entry.get("id") == key_id:
            return
    raise DeviceManifestError(
        "{} is not authorized by {}".format(subject, relationship)
    )
