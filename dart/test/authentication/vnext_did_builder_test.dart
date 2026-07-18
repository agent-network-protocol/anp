import 'dart:convert';
import 'dart:io';

import 'package:anp/anp.dart';
import 'package:test/test.dart';

void main() {
  test('shared vNext DID build/add/update/remove vectors', () {
    final fixture = _fixture();
    final base = _map(fixture['base_document']);
    final baseBefore = _clone(base);
    final built = _build(fixture);

    expect(built, equals(fixture['expected_build']));
    expect(base, equals(baseBefore));
    expect(built['x-example'], equals(base['x-example']));

    final withStaleProof = _clone(built)
      ..['proof'] = <String, Object?>{'proofValue': 'stale'};
    final deviceB = _map(fixture['device_b']);
    final added = addDeviceToDidDocument(
      withStaleProof,
      fixture['root_key_id']! as String,
      _entry(deviceB),
      _map(deviceB['signing_verification_method']),
      _map(deviceB['e2ee_verification_method']),
      _retiredIds(fixture),
    );
    expect(added, equals(fixture['expected_add']));
    expect(added, isNot(contains('proof')));
    expect(withStaleProof, contains('proof'));

    final rotated = _map(fixture['device_b_rotated']);
    final updated = updateDeviceInDidDocument(
      added,
      fixture['root_key_id']! as String,
      _entry(rotated),
      _map(rotated['signing_verification_method']),
      _map(rotated['e2ee_verification_method']),
    );
    expect(updated, equals(fixture['expected_update']));

    final removed = removeDeviceFromDidDocument(
      updated,
      fixture['root_key_id']! as String,
      _map(rotated['entry'])['device_id']! as String,
    );
    expect(removed, equals(fixture['expected_remove']));
    expect(
      _map(removed['deviceManifest'])['devices'],
      equals(_map(built['deviceManifest'])['devices']),
    );
    expect(validateDeviceManifest(removed), isNotNull);

    final multikeyBuilt = buildVNextDidDocument(
      _map(fixture['base_document']),
      fixture['root_key_id']! as String,
      _map(fixture['root_verification_method']),
      _entry(_map(fixture['device_a'])),
      _map(_map(fixture['device_a'])['signing_verification_method']),
      _map(fixture['x25519_multikey_verification_method']),
    );
    expect(
      (multikeyBuilt['verificationMethod']! as List)[2],
      equals(fixture['x25519_multikey_verification_method']),
    );
  });

  test('builder rejects root as device key and private material', () {
    final fixture = _fixture();
    final rootKeyId = fixture['root_key_id']! as String;
    final device = _clone(_map(fixture['device_a']));
    final rootDeviceEntry = _clone(_map(device['entry']))
      ..['signing_key_id'] = rootKeyId;
    device['entry'] = rootDeviceEntry;
    device['signing_verification_method'] = _clone(
      _map(fixture['root_verification_method']),
    );
    expect(
      () => buildVNextDidDocument(
        _map(fixture['base_document']),
        rootKeyId,
        _map(fixture['root_verification_method']),
        _entry(device),
        _map(device['signing_verification_method']),
        _map(device['e2ee_verification_method']),
      ),
      throwsA(isA<AnpAuthenticationException>()),
    );

    final privateRoot = _clone(_map(fixture['root_verification_method']));
    final privateJwk = _clone(_map(privateRoot['publicKeyJwk']))
      ..['d'] = 'PRIVATE';
    privateRoot['publicKeyJwk'] = privateJwk;
    expect(
      () => buildVNextDidDocument(
        _map(fixture['base_document']),
        rootKeyId,
        privateRoot,
        _entry(_map(fixture['device_a'])),
        _map(_map(fixture['device_a'])['signing_verification_method']),
        _map(_map(fixture['device_a'])['e2ee_verification_method']),
      ),
      throwsA(isA<AnpAuthenticationException>()),
    );

    final privateBase = _clone(_map(fixture['base_document']))
      ..['root_private_key'] = 'PRIVATE';
    expect(
      () => buildVNextDidDocument(
        privateBase,
        rootKeyId,
        _map(fixture['root_verification_method']),
        _entry(_map(fixture['device_a'])),
        _map(_map(fixture['device_a'])['signing_verification_method']),
        _map(_map(fixture['device_a'])['e2ee_verification_method']),
      ),
      throwsA(isA<AnpAuthenticationException>()),
    );
  });

  test('mutation rejects duplicate, foreign, and missing relationship', () {
    final fixture = _fixture();
    final built = _build(fixture);
    final rootKeyId = fixture['root_key_id']! as String;
    final deviceA = _map(fixture['device_a']);
    expect(
      () => addDeviceToDidDocument(
        built,
        rootKeyId,
        _entry(deviceA),
        _map(deviceA['signing_verification_method']),
        _map(deviceA['e2ee_verification_method']),
        _retiredIds(fixture),
      ),
      throwsA(isA<AnpAuthenticationException>()),
    );

    final deviceB = _map(fixture['device_b']);
    final foreign = _clone(_map(deviceB['signing_verification_method']))
      ..['controller'] = 'did:example:other';
    expect(
      () => addDeviceToDidDocument(
        built,
        rootKeyId,
        _entry(deviceB),
        foreign,
        _map(deviceB['e2ee_verification_method']),
        _retiredIds(fixture),
      ),
      throwsA(isA<AnpAuthenticationException>()),
    );

    final missingRelationship = _clone(built)..['keyAgreement'] = <Object?>[];
    expect(
      () => addDeviceToDidDocument(
        missingRelationship,
        rootKeyId,
        _entry(deviceB),
        _map(deviceB['signing_verification_method']),
        _map(deviceB['e2ee_verification_method']),
        _retiredIds(fixture),
      ),
      throwsA(isA<AnpAuthenticationException>()),
    );
  });

  test('builder rejects malformed or role-incompatible public keys', () {
    final fixture = _fixture();
    for (final rawCase in fixture['invalid_public_key_cases']! as List) {
      final invalidCase = _map(rawCase);
      final role = invalidCase['role']! as String;
      final root = _clone(_map(fixture['root_verification_method']));
      final device = _clone(_map(fixture['device_a']));
      if (role == 'root') {
        expect(
          () => _buildWith(
            fixture,
            rootVerificationMethod: _map(invalidCase['verification_method']),
          ),
          throwsA(isA<AnpAuthenticationException>()),
          reason: invalidCase['name']! as String,
        );
      } else {
        final field = role == 'device_signing'
            ? 'signing_verification_method'
            : 'e2ee_verification_method';
        device[field] = _clone(_map(invalidCase['verification_method']));
        expect(
          () => buildVNextDidDocument(
            _map(fixture['base_document']),
            fixture['root_key_id']! as String,
            root,
            _entry(device),
            _map(device['signing_verification_method']),
            _map(device['e2ee_verification_method']),
          ),
          throwsA(isA<AnpAuthenticationException>()),
          reason: invalidCase['name']! as String,
        );
      }
    }
  });

  test('builder rejects duplicate key material across IDs and encodings', () {
    final fixture = _fixture();
    final built = _build(fixture);
    final rootKeyId = fixture['root_key_id']! as String;
    for (final rawCase in fixture['duplicate_key_material_cases']! as List) {
      final invalidCase = _map(rawCase);
      if (invalidCase['operation'] == 'build') {
        expect(
          () => _buildWith(
            fixture,
            rootVerificationMethod: _map(
              invalidCase['root_verification_method'],
            ),
          ),
          throwsA(isA<AnpAuthenticationException>()),
          reason: invalidCase['name']! as String,
        );
        continue;
      }
      final device = _clone(_map(fixture['device_b']));
      for (final field in const [
        'signing_verification_method',
        'e2ee_verification_method',
      ]) {
        if (invalidCase.containsKey(field)) {
          device[field] = _clone(_map(invalidCase[field]));
        }
      }
      expect(
        () => addDeviceToDidDocument(
          built,
          rootKeyId,
          _entry(device),
          _map(device['signing_verification_method']),
          _map(device['e2ee_verification_method']),
          _retiredIds(fixture),
        ),
        throwsA(isA<AnpAuthenticationException>()),
        reason: invalidCase['name']! as String,
      );
    }
  });

  test('mutation rejects cross-role relationship pollution', () {
    final fixture = _fixture();
    final built = _build(fixture);
    final deviceB = _map(fixture['device_b']);
    for (final rawCase in fixture['invalid_relationship_cases']! as List) {
      final invalidCase = _map(rawCase);
      final polluted = _clone(built);
      (polluted[invalidCase['relationship']]! as List).add(
        invalidCase['key_id'],
      );
      expect(
        () => addDeviceToDidDocument(
          polluted,
          fixture['root_key_id']! as String,
          _entry(deviceB),
          _map(deviceB['signing_verification_method']),
          _map(deviceB['e2ee_verification_method']),
          _retiredIds(fixture),
        ),
        throwsA(isA<AnpAuthenticationException>()),
        reason: invalidCase['name']! as String,
      );
    }
  });

  test('removed device IDs cannot be reused when retired', () {
    final fixture = _fixture();
    final rootKeyId = fixture['root_key_id']! as String;
    final deviceB = _map(fixture['device_b']);
    final added = addDeviceToDidDocument(
      _build(fixture),
      rootKeyId,
      _entry(deviceB),
      _map(deviceB['signing_verification_method']),
      _map(deviceB['e2ee_verification_method']),
      _retiredIds(fixture),
    );
    final deviceId = _map(deviceB['entry'])['device_id']! as String;
    final signingKeyId = _map(deviceB['entry'])['signing_key_id']! as String;
    final e2eeKeyId = _map(deviceB['entry'])['e2ee_key_id']! as String;
    (added['authentication']! as List).add(signingKeyId);
    (added['assertionMethod']! as List).add(signingKeyId);
    (added['keyAgreement']! as List).add(e2eeKeyId);
    final rotated = _map(fixture['device_b_rotated']);
    final updated = updateDeviceInDidDocument(
      added,
      rootKeyId,
      _entry(rotated),
      _map(rotated['signing_verification_method']),
      _map(rotated['e2ee_verification_method']),
    );
    for (final relationship in const [
      'authentication',
      'assertionMethod',
      'keyAgreement',
    ]) {
      expect(
        (updated[relationship]! as List).any(
          (entry) =>
              entry == signingKeyId ||
              entry == e2eeKeyId ||
              entry is Map &&
                  (entry['id'] == signingKeyId || entry['id'] == e2eeKeyId),
        ),
        isFalse,
      );
    }
    final removed = removeDeviceFromDidDocument(added, rootKeyId, deviceId);
    expect(
      () => addDeviceToDidDocument(
        removed,
        rootKeyId,
        _entry(deviceB),
        _map(deviceB['signing_verification_method']),
        _map(deviceB['e2ee_verification_method']),
        [deviceId],
      ),
      throwsA(isA<AnpAuthenticationException>()),
    );
    expect(
      () => addDeviceToDidDocument(
        removed,
        rootKeyId,
        _entry(deviceB),
        _map(deviceB['signing_verification_method']),
        _map(deviceB['e2ee_verification_method']),
        const [''],
      ),
      throwsA(isA<AnpAuthenticationException>()),
    );
  });

  test('builder rejects non-JSON and non-finite extension values', () {
    final fixture = _fixture();
    for (final invalidValue in <Object?>[
      double.nan,
      double.infinity,
      DateTime(0),
    ]) {
      final base = _clone(_map(fixture['base_document']))
        ..['x-invalid'] = invalidValue;
      expect(
        () => buildVNextDidDocument(
          base,
          fixture['root_key_id']! as String,
          _map(fixture['root_verification_method']),
          _entry(_map(fixture['device_a'])),
          _map(_map(fixture['device_a'])['signing_verification_method']),
          _map(_map(fixture['device_a'])['e2ee_verification_method']),
        ),
        throwsA(isA<AnpAuthenticationException>()),
      );
    }

    const largeInteger = 9007199254740993;
    final base = _clone(_map(fixture['base_document']))
      ..['x-large-integer'] = largeInteger;
    final built = buildVNextDidDocument(
      base,
      fixture['root_key_id']! as String,
      _map(fixture['root_verification_method']),
      _entry(_map(fixture['device_a'])),
      _map(_map(fixture['device_a'])['signing_verification_method']),
      _map(_map(fixture['device_a'])['e2ee_verification_method']),
    );
    expect(built['x-large-integer'], equals(largeInteger));
  });
}

JsonMap _fixture() {
  final file = File(
    '../testdata/device_manifest/vnext_did_builder_fixtures.json',
  );
  return _map(jsonDecode(file.readAsStringSync()));
}

JsonMap _build(JsonMap fixture) {
  return _buildWith(fixture);
}

JsonMap _buildWith(JsonMap fixture, {JsonMap? rootVerificationMethod}) {
  final device = _map(fixture['device_a']);
  return buildVNextDidDocument(
    _map(fixture['base_document']),
    fixture['root_key_id']! as String,
    rootVerificationMethod ?? _map(fixture['root_verification_method']),
    _entry(device),
    _map(device['signing_verification_method']),
    _map(device['e2ee_verification_method']),
  );
}

List<String> _retiredIds(JsonMap fixture) =>
    List<String>.from(fixture['retired_device_ids']! as List);

DeviceManifestEntry _entry(JsonMap device) {
  final value = _map(device['entry']);
  return DeviceManifestEntry(
    deviceId: value['device_id']! as String,
    signingKeyId: value['signing_key_id']! as String,
    e2eeKeyId: value['e2ee_key_id']! as String,
    profiles: List<String>.from(value['profiles']! as List),
  );
}

JsonMap _map(Object? value) => Map<String, Object?>.from(value! as Map);

JsonMap _clone(JsonMap value) => _map(jsonDecode(jsonEncode(value)));
