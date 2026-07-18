"""Typed ANP vNext Device Manifest parsing and validation."""

from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple


DEVICE_MANIFEST_TYPE = "ANPDeviceManifest"

PROFILE_CORE_BINDING_V2 = "anp.core.binding.v2"
PROFILE_IDENTITY_DISCOVERY_V2 = "anp.identity.discovery.v2"
PROFILE_DIRECT_BASE_V2 = "anp.direct.base.v2"
PROFILE_GROUP_BASE_V2 = "anp.group.base.v2"
PROFILE_DIRECT_E2EE_V2 = "anp.direct.e2ee.v2"
PROFILE_GROUP_E2EE_V2 = "anp.group.e2ee.v2"

_MANIFEST_FIELDS = frozenset({"type", "devices"})
_ENTRY_FIELDS = frozenset(
    {"device_id", "signing_key_id", "e2ee_key_id", "profiles"}
)
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
        raise DeviceManifestError(
            "deviceManifest.type must equal ANPDeviceManifest"
        )

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
        raise DeviceManifestError(
            "DID document verificationMethod must be an array"
        )

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
            raise DeviceManifestError(
                "signing_key_id and e2ee_key_id must be distinct"
            )
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


def _require_exact_fields(
    value: Dict[str, Any], expected: frozenset, subject: str
) -> None:
    if set(value) != expected:
        raise DeviceManifestError(
            "{} must contain exactly {}".format(
                subject, ", ".join(sorted(expected))
            )
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
        raise DeviceManifestError(
            "{} requires {}".format(subject, relationship)
        )
    for entry in entries:
        if entry == key_id:
            return
        if isinstance(entry, dict) and entry.get("id") == key_id:
            return
    raise DeviceManifestError(
        "{} is not authorized by {}".format(subject, relationship)
    )
