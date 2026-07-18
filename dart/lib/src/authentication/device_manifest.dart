import 'dart:convert';
import 'dart:typed_data';

import '../codec/base58.dart';
import '../errors.dart';
import '../keys/jwk.dart';
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
const Set<String> _signingAlgorithms = {'Ed25519', 'P-256', 'secp256k1'};
final RegExp _base64UrlPattern = RegExp(r'^[A-Za-z0-9_-]+$');

class _PublicKeyIdentity {
  const _PublicKeyIdentity(this.algorithm, this.rawPublicKey);

  final String algorithm;
  final Uint8List rawPublicKey;

  String get materialId => base64UrlEncode(rawPublicKey).replaceAll('=', '');
}

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

/// Builds an unsigned vNext DID document from public key material only.
///
/// The caller must root-sign the returned document before publishing it.
JsonMap buildVNextDidDocument(
  JsonMap baseDocument,
  String rootKeyId,
  JsonMap rootVerificationMethod,
  DeviceManifestEntry device,
  JsonMap deviceSigningVerificationMethod,
  JsonMap deviceE2eeVerificationMethod,
) {
  final document = _deepCloneJsonMap(baseDocument);
  for (final field in const [
    'verificationMethod',
    'authentication',
    'assertionMethod',
    'keyAgreement',
    'deviceManifest',
    'proof',
  ]) {
    if (document.containsKey(field)) {
      throw AnpAuthenticationException(
        'base DID document must not contain managed field $field',
      );
    }
  }

  final did = _documentDid(document);
  _validateRootMethod(did, rootKeyId, rootVerificationMethod);
  _validateDeviceMethods(
    did,
    rootKeyId,
    device,
    deviceSigningVerificationMethod,
    deviceE2eeVerificationMethod,
  );
  document.addAll({
    'verificationMethod': [
      _deepCloneJsonMap(rootVerificationMethod),
      _deepCloneJsonMap(deviceSigningVerificationMethod),
      _deepCloneJsonMap(deviceE2eeVerificationMethod),
    ],
    'authentication': [device.signingKeyId],
    'assertionMethod': [rootKeyId, device.signingKeyId],
    'keyAgreement': [device.e2eeKeyId],
    'deviceManifest': {
      'type': deviceManifestType,
      'devices': [device.toJson()],
    },
  });
  _validateVNextDocument(document, rootKeyId);
  return document;
}

/// Adds one device to a validated document and returns an unsigned copy.
JsonMap addDeviceToDidDocument(
  JsonMap didDocument,
  String rootKeyId,
  DeviceManifestEntry device,
  JsonMap deviceSigningVerificationMethod,
  JsonMap deviceE2eeVerificationMethod,
  Iterable<String> retiredDeviceIds,
) {
  final document = _prepareDocumentForMutation(didDocument, rootKeyId);
  final manifest = validateDeviceManifest(document);
  if (manifest == null) {
    throw const AnpAuthenticationException(
      'deviceManifest is required for device update',
    );
  }
  if (manifest.devices.any((entry) => entry.deviceId == device.deviceId)) {
    throw const AnpAuthenticationException('device_id already exists');
  }
  final retired = _validateRetiredDeviceIds(retiredDeviceIds);
  if (retired.contains(device.deviceId)) {
    throw const AnpAuthenticationException(
      'retired device_id cannot be reused',
    );
  }
  _appendDeviceMaterial(
    document,
    rootKeyId,
    device,
    deviceSigningVerificationMethod,
    deviceE2eeVerificationMethod,
  );
  _validateVNextDocument(document, rootKeyId);
  return document;
}

/// Replaces one device's public keys and Profile entry in an unsigned copy.
JsonMap updateDeviceInDidDocument(
  JsonMap didDocument,
  String rootKeyId,
  DeviceManifestEntry device,
  JsonMap deviceSigningVerificationMethod,
  JsonMap deviceE2eeVerificationMethod,
) {
  final document = _prepareDocumentForMutation(didDocument, rootKeyId);
  final manifest = validateDeviceManifest(document);
  if (manifest == null) {
    throw const AnpAuthenticationException(
      'deviceManifest is required for device update',
    );
  }
  DeviceManifestEntry? oldEntry;
  for (final entry in manifest.devices) {
    if (entry.deviceId == device.deviceId) {
      oldEntry = entry;
      break;
    }
  }
  if (oldEntry == null) {
    throw const AnpAuthenticationException('device_id does not exist');
  }
  _removeDeviceMaterial(document, oldEntry);
  _appendDeviceMaterial(
    document,
    rootKeyId,
    device,
    deviceSigningVerificationMethod,
    deviceE2eeVerificationMethod,
  );
  _validateVNextDocument(document, rootKeyId);
  return document;
}

/// Removes one device and its active key references from an unsigned copy.
JsonMap removeDeviceFromDidDocument(
  JsonMap didDocument,
  String rootKeyId,
  String deviceId,
) {
  final document = _prepareDocumentForMutation(didDocument, rootKeyId);
  final manifest = validateDeviceManifest(document);
  if (manifest == null) {
    throw const AnpAuthenticationException(
      'deviceManifest is required for device update',
    );
  }
  DeviceManifestEntry? oldEntry;
  for (final entry in manifest.devices) {
    if (entry.deviceId == deviceId) {
      oldEntry = entry;
      break;
    }
  }
  if (oldEntry == null) {
    throw const AnpAuthenticationException('device_id does not exist');
  }
  _removeDeviceMaterial(document, oldEntry);
  _validateVNextDocument(document, rootKeyId);
  return document;
}

JsonMap _prepareDocumentForMutation(JsonMap didDocument, String rootKeyId) {
  _validateVNextDocument(didDocument, rootKeyId);
  final document = _deepCloneJsonMap(didDocument);
  // A mutation invalidates any existing root proof. The caller must sign the
  // returned unsigned document instead of accidentally publishing stale proof.
  document.remove('proof');
  return document;
}

void _validateVNextDocument(JsonMap didDocument, String rootKeyId) {
  _validateJsonValue(didDocument, 'DID document');
  _rejectPrivateKeyMaterial(didDocument, 'DID document');
  final did = _documentDid(didDocument);
  final methods = _requireArray(
    didDocument['verificationMethod'],
    'DID document verificationMethod',
  );
  final rootMethods = methods.where((method) {
    return method is Map && method['id'] == rootKeyId;
  }).toList();
  if (rootMethods.length != 1) {
    throw const AnpAuthenticationException(
      'root key must resolve exactly once in verificationMethod',
    );
  }
  final rootIdentity = _validateRootMethod(
    did,
    rootKeyId,
    _requireMap(rootMethods.single, 'DID root verification method'),
  );
  _requireRelationship(
    didDocument,
    'assertionMethod',
    rootKeyId,
    'DID root key',
  );
  final manifest = validateDeviceManifest(didDocument);
  if (manifest == null) {
    throw const AnpAuthenticationException('deviceManifest is required');
  }
  final seenMaterial = <String>{rootIdentity.materialId};
  for (final device in manifest.devices) {
    if (device.signingKeyId == rootKeyId || device.e2eeKeyId == rootKeyId) {
      throw const AnpAuthenticationException(
        'DID root key cannot be a device key',
      );
    }
    final identities = _validateDeviceMethods(
      did,
      rootKeyId,
      device,
      _uniqueVerificationMethod(didDocument, device.signingKeyId),
      _uniqueVerificationMethod(didDocument, device.e2eeKeyId),
    );
    _requireRelationship(
      didDocument,
      'authentication',
      device.signingKeyId,
      'device signing key',
    );
    _requireRelationship(
      didDocument,
      'assertionMethod',
      device.signingKeyId,
      'device signing key',
    );
    _requireRelationship(
      didDocument,
      'keyAgreement',
      device.e2eeKeyId,
      'device E2EE key',
    );
    if (_relationshipContains(
      didDocument,
      'keyAgreement',
      device.signingKeyId,
    )) {
      throw const AnpAuthenticationException(
        'device signing key must not be in keyAgreement',
      );
    }
    if (_relationshipContains(
          didDocument,
          'authentication',
          device.e2eeKeyId,
        ) ||
        _relationshipContains(
          didDocument,
          'assertionMethod',
          device.e2eeKeyId,
        )) {
      throw const AnpAuthenticationException(
        'device E2EE key must not be a signing relationship',
      );
    }
    for (final identity in [identities.$1, identities.$2]) {
      if (!seenMaterial.add(identity.materialId)) {
        throw const AnpAuthenticationException(
          'root and device public key material must be unique',
        );
      }
    }
  }
}

String _documentDid(JsonMap document) =>
    _requireNonEmptyString(document['id'], 'DID document id');

_PublicKeyIdentity _validateRootMethod(
  String did,
  String rootKeyId,
  JsonMap method,
) {
  return _validatePublicMethod(
    did,
    rootKeyId,
    method,
    allowedAlgorithms: _signingAlgorithms,
    subject: 'DID root verification method',
  );
}

(_PublicKeyIdentity, _PublicKeyIdentity) _validateDeviceMethods(
  String did,
  String rootKeyId,
  DeviceManifestEntry device,
  JsonMap signingMethod,
  JsonMap e2eeMethod,
) {
  if (device.signingKeyId == rootKeyId || device.e2eeKeyId == rootKeyId) {
    throw const AnpAuthenticationException(
      'DID root key cannot be a device key',
    );
  }
  final requiresStandardObjectProof = device.profiles.any(
    (profile) =>
        profile == profileDirectE2eeV2 || profile == profileGroupE2eeV2,
  );
  final signingIdentity = _validatePublicMethod(
    did,
    device.signingKeyId,
    signingMethod,
    allowedAlgorithms: requiresStandardObjectProof
        ? const {'Ed25519'}
        : _signingAlgorithms,
    subject: 'device signing verification method',
  );
  final e2eeIdentity = _validatePublicMethod(
    did,
    device.e2eeKeyId,
    e2eeMethod,
    allowedAlgorithms: const {'X25519'},
    subject: 'device E2EE verification method',
  );
  if (signingIdentity.materialId == e2eeIdentity.materialId) {
    throw const AnpAuthenticationException(
      'device key material must be unique across roles',
    );
  }
  return (signingIdentity, e2eeIdentity);
}

_PublicKeyIdentity _validatePublicMethod(
  String did,
  String expectedKeyId,
  JsonMap method, {
  required Set<String> allowedAlgorithms,
  required String subject,
}) {
  _validateJsonValue(method, subject);
  if (method['id'] != expectedKeyId) {
    throw AnpAuthenticationException('$subject id does not match its role');
  }
  if (method['controller'] != did) {
    throw AnpAuthenticationException('$subject controller must match the DID');
  }
  _validateSameDocumentKeyId(did, expectedKeyId);
  _rejectPrivateKeyMaterial(method, subject);
  final methodType = _requireNonEmptyString(method['type'], '$subject.type');
  final materialFields = const [
    'publicKeyJwk',
    'publicKeyMultibase',
    'publicKeyBase58',
  ].where(method.containsKey).toList();
  if (materialFields.length != 1) {
    throw AnpAuthenticationException(
      '$subject must contain exactly one supported public key field',
    );
  }
  final identity = switch (materialFields.single) {
    'publicKeyJwk' => _decodePublicJwk(
      methodType,
      method['publicKeyJwk'],
      subject,
    ),
    'publicKeyMultibase' => _decodePublicMultikey(
      methodType,
      method['publicKeyMultibase'],
      subject,
    ),
    _ => throw AnpAuthenticationException(
      '$subject publicKeyBase58 is not supported by vNext helpers',
    ),
  };
  if (!allowedAlgorithms.contains(identity.algorithm)) {
    throw AnpAuthenticationException('$subject uses the wrong key algorithm');
  }
  return identity;
}

void _validateSameDocumentKeyId(String did, String keyId) {
  if (!keyId.startsWith('$did#') || keyId == '$did#') {
    throw const AnpAuthenticationException(
      'key id must be a DID URL in the same document',
    );
  }
}

_PublicKeyIdentity _decodePublicJwk(
  String methodType,
  Object? value,
  String subject,
) {
  if (!const {
    'JsonWebKey2020',
    'EcdsaSecp256k1VerificationKey2019',
    'EcdsaSecp256r1VerificationKey2019',
  }.contains(methodType)) {
    throw AnpAuthenticationException(
      '$subject type is incompatible with publicKeyJwk',
    );
  }
  final jwk = _requireMap(value, '$subject.publicKeyJwk');
  final kty = jwk['kty'];
  final curve = jwk['crv'];
  if (kty == 'OKP' && (curve == 'Ed25519' || curve == 'X25519')) {
    if (methodType != 'JsonWebKey2020') {
      throw AnpAuthenticationException('$subject type contradicts its JWK');
    }
    return _PublicKeyIdentity(
      curve! as String,
      _decodeCanonicalBase64Url32(jwk['x'], '$subject.x'),
    );
  }
  if (kty == 'EC' && (curve == 'P-256' || curve == 'secp256k1')) {
    final expectedType = curve == 'P-256'
        ? 'EcdsaSecp256r1VerificationKey2019'
        : 'EcdsaSecp256k1VerificationKey2019';
    if (methodType != 'JsonWebKey2020' && methodType != expectedType) {
      throw AnpAuthenticationException('$subject type contradicts its JWK');
    }
    final x = _decodeCanonicalBase64Url32(jwk['x'], '$subject.x');
    final y = _decodeCanonicalBase64Url32(jwk['y'], '$subject.y');
    try {
      publicKeyFromJwk(jwk);
    } on AnpCryptoException catch (error) {
      throw AnpAuthenticationException(
        '$subject contains an invalid EC point',
        cause: error,
      );
    }
    return _PublicKeyIdentity(
      curve! as String,
      Uint8List.fromList([...x, ...y]),
    );
  }
  throw AnpAuthenticationException(
    '$subject contains an unsupported public JWK',
  );
}

_PublicKeyIdentity _decodePublicMultikey(
  String methodType,
  Object? value,
  String subject,
) {
  if (methodType != 'Multikey' && methodType != 'X25519KeyAgreementKey2019') {
    throw AnpAuthenticationException(
      '$subject type is incompatible with publicKeyMultibase',
    );
  }
  if (value is! String || !value.startsWith('z') || value.length == 1) {
    throw AnpAuthenticationException(
      '$subject.publicKeyMultibase must be base58btc',
    );
  }
  late Uint8List decoded;
  try {
    decoded = decodeBase58(value.substring(1));
  } on AnpCodecException catch (error) {
    throw AnpAuthenticationException(
      '$subject.publicKeyMultibase is invalid',
      cause: error,
    );
  }
  if ('z${encodeBase58(decoded)}' != value) {
    throw AnpAuthenticationException(
      '$subject.publicKeyMultibase must be canonical',
    );
  }
  if (decoded.length != 34) {
    throw AnpAuthenticationException(
      '$subject.publicKeyMultibase must contain a 32-byte key',
    );
  }
  late String algorithm;
  if (decoded[0] == 0xed && decoded[1] == 0x01) {
    algorithm = 'Ed25519';
  } else if (decoded[0] == 0xec && decoded[1] == 0x01) {
    algorithm = 'X25519';
  } else {
    throw AnpAuthenticationException(
      '$subject.publicKeyMultibase uses an unsupported codec',
    );
  }
  if (methodType == 'X25519KeyAgreementKey2019' && algorithm != 'X25519') {
    throw AnpAuthenticationException('$subject type contradicts its Multikey');
  }
  return _PublicKeyIdentity(algorithm, Uint8List.fromList(decoded.sublist(2)));
}

Uint8List _decodeCanonicalBase64Url32(Object? value, String subject) {
  if (value is! String || !_base64UrlPattern.hasMatch(value)) {
    throw AnpAuthenticationException('$subject must be unpadded base64url');
  }
  late Uint8List decoded;
  try {
    final normalized = value.padRight(
      value.length + ((4 - value.length % 4) % 4),
      '=',
    );
    decoded = Uint8List.fromList(base64Url.decode(normalized));
  } on FormatException catch (error) {
    throw AnpAuthenticationException(
      '$subject is invalid base64url',
      cause: error,
    );
  }
  final canonical = base64UrlEncode(decoded).replaceAll('=', '');
  if (decoded.length != 32 || canonical != value) {
    throw AnpAuthenticationException(
      '$subject must canonically encode 32 bytes',
    );
  }
  return decoded;
}

void _rejectPrivateKeyMaterial(Object? value, String subject) {
  if (value is Map) {
    for (final entry in value.entries) {
      final key = entry.key;
      if (key is String &&
          (key
                  .toLowerCase()
                  .replaceAll('_', '')
                  .replaceAll('-', '')
                  .contains('privatekey') ||
              key == 'd' && value.containsKey('kty'))) {
        throw AnpAuthenticationException(
          '$subject must not contain private key material',
        );
      }
      _rejectPrivateKeyMaterial(entry.value, subject);
    }
  } else if (value is List) {
    for (final nested in value) {
      _rejectPrivateKeyMaterial(nested, subject);
    }
  }
}

JsonMap _uniqueVerificationMethod(JsonMap didDocument, String keyId) {
  final methods = _requireArray(
    didDocument['verificationMethod'],
    'DID document verificationMethod',
  );
  final matches = methods.where((method) {
    return method is Map && method['id'] == keyId;
  }).toList();
  if (matches.length != 1) {
    throw const AnpAuthenticationException(
      'key id must resolve exactly once in verificationMethod',
    );
  }
  return _requireMap(matches.single, 'verification method');
}

void _appendDeviceMaterial(
  JsonMap document,
  String rootKeyId,
  DeviceManifestEntry device,
  JsonMap signingMethod,
  JsonMap e2eeMethod,
) {
  final did = _documentDid(document);
  _validateDeviceMethods(did, rootKeyId, device, signingMethod, e2eeMethod);
  _requireArray(
    document['verificationMethod'],
    'verificationMethod',
  ).addAll([_deepCloneJsonMap(signingMethod), _deepCloneJsonMap(e2eeMethod)]);
  _requireArray(
    document['authentication'],
    'authentication',
  ).add(device.signingKeyId);
  _requireArray(
    document['assertionMethod'],
    'assertionMethod',
  ).add(device.signingKeyId);
  _requireArray(document['keyAgreement'], 'keyAgreement').add(device.e2eeKeyId);
  final manifest = _requireMap(document['deviceManifest'], 'deviceManifest');
  _requireArray(
    manifest['devices'],
    'deviceManifest.devices',
  ).add(device.toJson());
}

void _removeDeviceMaterial(JsonMap document, DeviceManifestEntry device) {
  final keyIds = {device.signingKeyId, device.e2eeKeyId};
  final methods = _requireArray(
    document['verificationMethod'],
    'verificationMethod',
  );
  methods.removeWhere(
    (method) => method is Map && keyIds.contains(method['id']),
  );
  for (final relationship in const [
    'authentication',
    'assertionMethod',
    'keyAgreement',
  ]) {
    _requireArray(document[relationship], relationship).removeWhere(
      (value) => keyIds.any((keyId) => _relationshipEntryIs(value, keyId)),
    );
  }
  final manifest = _requireMap(document['deviceManifest'], 'deviceManifest');
  _requireArray(manifest['devices'], 'deviceManifest.devices').removeWhere(
    (entry) => entry is Map && entry['device_id'] == device.deviceId,
  );
}

bool _relationshipEntryIs(Object? entry, String keyId) {
  return entry == keyId || entry is Map && entry['id'] == keyId;
}

bool _relationshipContains(
  JsonMap didDocument,
  String relationship,
  String keyId,
) {
  final entries = didDocument[relationship];
  return entries is List &&
      entries.any((entry) => _relationshipEntryIs(entry, keyId));
}

List<Object?> _requireArray(Object? value, String subject) {
  if (value is! List) {
    throw AnpAuthenticationException('$subject must be an array');
  }
  return value;
}

JsonMap _deepCloneJsonMap(JsonMap value) {
  _validateJsonValue(value, 'DID document');
  final decoded = jsonDecode(jsonEncode(value));
  if (decoded is! Map) {
    throw const AnpAuthenticationException('DID document must be an object');
  }
  return Map<String, Object?>.from(decoded);
}

void _validateJsonValue(Object? value, String subject) {
  if (value == null || value is String || value is bool || value is int) {
    return;
  }
  if (value is double) {
    if (!value.isFinite) {
      throw AnpAuthenticationException('$subject contains a non-finite number');
    }
    return;
  }
  if (value is List) {
    for (final nested in value) {
      _validateJsonValue(nested, subject);
    }
    return;
  }
  if (value is Map) {
    for (final entry in value.entries) {
      if (entry.key is! String) {
        throw AnpAuthenticationException(
          '$subject contains a non-string object key',
        );
      }
      _validateJsonValue(entry.value, subject);
    }
    return;
  }
  throw AnpAuthenticationException('$subject contains a non-JSON value');
}

Set<String> _validateRetiredDeviceIds(Iterable<String> retiredDeviceIds) {
  final retired = <String>{};
  for (final deviceId in retiredDeviceIds) {
    retired.add(_requireNonEmptyString(deviceId, 'retired device_id'));
  }
  return retired;
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
