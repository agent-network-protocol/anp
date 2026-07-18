import '../errors.dart';
import 'types.dart';

const String deviceManifestType = 'ANPDeviceManifest';

const String profileCoreBindingV2 = 'anp.core.binding.v2';
const String profileIdentityDiscoveryV2 = 'anp.identity.discovery.v2';
const String profileDirectBaseV2 = 'anp.direct.base.v2';
const String profileGroupBaseV2 = 'anp.group.base.v2';
const String profileDirectE2eeV2 = 'anp.direct.e2ee.v2';
const String profileGroupE2eeV2 = 'anp.group.e2ee.v2';

const Set<String> _manifestFields = {'type', 'devices'};
const Set<String> _entryFields = {
  'device_id',
  'signing_key_id',
  'e2ee_key_id',
  'profiles',
};
const Set<String> _p5Dependencies = {
  profileCoreBindingV2,
  profileIdentityDiscoveryV2,
  profileDirectBaseV2,
  profileDirectE2eeV2,
};
const Set<String> _p6Dependencies = {
  profileCoreBindingV2,
  profileIdentityDiscoveryV2,
  profileGroupBaseV2,
  profileGroupE2eeV2,
};

/// One public cryptographic device endpoint in a Device Manifest.
class DeviceManifestEntry {
  const DeviceManifestEntry({
    required this.deviceId,
    required this.signingKeyId,
    required this.e2eeKeyId,
    required this.profiles,
  });

  final String deviceId;
  final String signingKeyId;
  final String e2eeKeyId;
  final List<String> profiles;

  JsonMap toJson() => {
    'device_id': deviceId,
    'signing_key_id': signingKeyId,
    'e2ee_key_id': e2eeKeyId,
    'profiles': List<String>.of(profiles),
  };
}

/// Typed value of the DID document `deviceManifest` extension.
class DeviceManifest {
  const DeviceManifest({required this.type, required this.devices});

  final String type;
  final List<DeviceManifestEntry> devices;

  JsonMap toJson() => {
    'type': type,
    'devices': devices.map((device) => device.toJson()).toList(),
  };
}

/// Parses the optional, closed vNext Device Manifest schema.
///
/// Unknown members elsewhere in [didDocument] are not interpreted or changed.
DeviceManifest? parseDeviceManifest(JsonMap didDocument) {
  if (!didDocument.containsKey('deviceManifest')) return null;

  final manifest = _requireMap(didDocument['deviceManifest'], 'deviceManifest');
  _requireExactFields(manifest, _manifestFields, 'deviceManifest');
  if (manifest['type'] != deviceManifestType) {
    throw const AnpAuthenticationException(
      'deviceManifest.type must equal ANPDeviceManifest',
    );
  }
  final rawDevices = manifest['devices'];
  if (rawDevices is! List) {
    throw const AnpAuthenticationException(
      'deviceManifest.devices must be an array',
    );
  }

  final devices = <DeviceManifestEntry>[];
  for (var index = 0; index < rawDevices.length; index++) {
    final subject = 'deviceManifest.devices[$index]';
    final entry = _requireMap(rawDevices[index], subject);
    _requireExactFields(entry, _entryFields, subject);
    final rawProfiles = entry['profiles'];
    if (rawProfiles is! List) {
      throw AnpAuthenticationException(
        '$subject.profiles must be a string array',
      );
    }
    devices.add(
      DeviceManifestEntry(
        deviceId: _requireString(entry['device_id'], '$subject.device_id'),
        signingKeyId: _requireString(
          entry['signing_key_id'],
          '$subject.signing_key_id',
        ),
        e2eeKeyId: _requireString(entry['e2ee_key_id'], '$subject.e2ee_key_id'),
        profiles: List<String>.unmodifiable(
          rawProfiles.map(
            (profile) => _requireString(profile, '$subject.profiles[]'),
          ),
        ),
      ),
    );
  }
  return DeviceManifest(
    type: deviceManifestType,
    devices: List<DeviceManifestEntry>.unmodifiable(devices),
  );
}

/// Parses and validates Manifest references, relationships, and dependencies.
DeviceManifest? validateDeviceManifest(JsonMap didDocument) {
  final manifest = parseDeviceManifest(didDocument);
  if (manifest == null) return null;

  final did = _requireNonEmptyString(didDocument['id'], 'DID document id');
  final rawMethods = didDocument['verificationMethod'];
  if (rawMethods is! List) {
    throw const AnpAuthenticationException(
      'DID document verificationMethod must be an array',
    );
  }
  final methodsById = <String, List<JsonMap>>{};
  for (final rawMethod in rawMethods) {
    if (rawMethod is! Map) continue;
    final method = _mapOrNull(rawMethod);
    final methodId = method?['id'];
    if (method != null && methodId is String) {
      methodsById.putIfAbsent(methodId, () => <JsonMap>[]).add(method);
    }
  }

  final seenDevices = <String>{};
  final seenKeys = <String>{};
  for (final device in manifest.devices) {
    _requireNonEmptyString(device.deviceId, 'device_id');
    _requireNonEmptyString(device.signingKeyId, 'signing_key_id');
    _requireNonEmptyString(device.e2eeKeyId, 'e2ee_key_id');
    if (device.profiles.isEmpty) {
      throw const AnpAuthenticationException('profiles must be non-empty');
    }
    for (final profile in device.profiles) {
      _requireNonEmptyString(profile, 'profile');
    }
    if (!seenDevices.add(device.deviceId)) {
      throw const AnpAuthenticationException('device_id must be unique');
    }
    if (device.signingKeyId == device.e2eeKeyId) {
      throw const AnpAuthenticationException(
        'signing_key_id and e2ee_key_id must be distinct',
      );
    }
    for (final keyId in [device.signingKeyId, device.e2eeKeyId]) {
      if (!seenKeys.add(keyId)) {
        throw const AnpAuthenticationException(
          'a verification method can belong to only one device entry',
        );
      }
      _validateSameDocumentMethod(did, keyId, methodsById);
    }

    final profiles = device.profiles.toSet();
    if (profiles.contains(profileDirectE2eeV2)) {
      _requireDependencies(profiles, _p5Dependencies, 'P5');
      _requireRelationship(
        didDocument,
        'assertionMethod',
        device.signingKeyId,
        'P5 signing key',
      );
    }
    if (profiles.contains(profileGroupE2eeV2)) {
      _requireDependencies(profiles, _p6Dependencies, 'P6');
      _requireRelationship(
        didDocument,
        'assertionMethod',
        device.signingKeyId,
        'P6 binding key',
      );
      _requireRelationship(
        didDocument,
        'authentication',
        device.signingKeyId,
        'P6 origin-proof key',
      );
    }
    _requireRelationship(
      didDocument,
      'keyAgreement',
      device.e2eeKeyId,
      'device E2EE key',
    );
  }
  return manifest;
}

/// Returns a validated device that declares [requiredProfile].
DeviceManifestEntry? findEligibleDevice(
  JsonMap didDocument,
  String deviceId,
  String requiredProfile,
) {
  final manifest = validateDeviceManifest(didDocument);
  if (manifest == null) return null;
  if (requiredProfile != profileDirectE2eeV2 &&
      requiredProfile != profileGroupE2eeV2) {
    return null;
  }
  for (final device in manifest.devices) {
    if (device.deviceId == deviceId &&
        device.profiles.contains(requiredProfile)) {
      return device;
    }
  }
  return null;
}

JsonMap _requireMap(Object? value, String subject) {
  if (value is! Map) {
    throw AnpAuthenticationException('$subject must be an object');
  }
  final result = _mapOrNull(value);
  if (result == null) {
    throw AnpAuthenticationException('$subject must use string keys');
  }
  return result;
}

JsonMap? _mapOrNull(Map<Object?, Object?> value) {
  if (value.keys.any((key) => key is! String)) return null;
  return Map<String, Object?>.from(value);
}

void _requireExactFields(JsonMap value, Set<String> expected, String subject) {
  if (value.length != expected.length ||
      value.keys.any((field) => !expected.contains(field))) {
    throw AnpAuthenticationException(
      '$subject has unexpected or missing members',
    );
  }
}

String _requireString(Object? value, String subject) {
  if (value is! String) {
    throw AnpAuthenticationException('$subject must be a string');
  }
  return value;
}

String _requireNonEmptyString(Object? value, String subject) {
  final result = _requireString(value, subject);
  if (result.isEmpty) {
    throw AnpAuthenticationException('$subject must be a non-empty string');
  }
  return result;
}

void _validateSameDocumentMethod(
  String did,
  String keyId,
  Map<String, List<JsonMap>> methodsById,
) {
  if (!keyId.startsWith('$did#') || keyId == '$did#') {
    throw const AnpAuthenticationException(
      'device key IDs must be DID URLs in the same DID document',
    );
  }
  final methods = methodsById[keyId] ?? const <JsonMap>[];
  if (methods.length != 1) {
    throw const AnpAuthenticationException(
      'device key ID must resolve exactly once in verificationMethod',
    );
  }
}

void _requireDependencies(
  Set<String> actual,
  Set<String> required,
  String profileName,
) {
  if (!actual.containsAll(required)) {
    throw AnpAuthenticationException(
      '$profileName device profile dependencies are incomplete',
    );
  }
}

void _requireRelationship(
  JsonMap didDocument,
  String relationship,
  String keyId,
  String subject,
) {
  final entries = didDocument[relationship];
  if (entries is List) {
    for (final entry in entries) {
      if (entry == keyId) return;
      if (entry is Map && entry['id'] == keyId) return;
    }
  }
  throw AnpAuthenticationException(
    '$subject is not authorized by $relationship',
  );
}
