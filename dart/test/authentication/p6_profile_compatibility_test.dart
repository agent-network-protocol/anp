import 'dart:convert';
import 'dart:io';

import 'package:anp/anp.dart';
import 'package:test/test.dart';

const _currentP6 = [
  'anp.core.binding.v1',
  'anp.identity.discovery.v1',
  'anp.group.base.v2',
  'anp.group.e2ee.v2',
];

void main() {
  final fixture = _map(
    jsonDecode(
      File(
        '../testdata/device_manifest/vnext_did_builder_fixtures.json',
      ).readAsStringSync(),
    ),
  );
  final rootKeyId = fixture['root_key_id']! as String;

  JsonMap device(String name, [List<String> profiles = _currentP6]) {
    final value = _clone(_map(fixture[name]));
    value['entry'] = _map(value['entry'])..['profiles'] = List.of(profiles);
    return value;
  }

  JsonMap build(JsonMap value) => buildVNextDidDocument(
    _map(fixture['base_document']),
    rootKeyId,
    _map(fixture['root_verification_method']),
    _entry(value),
    _map(value['signing_verification_method']),
    _map(value['e2ee_verification_method']),
  );

  JsonMap add(JsonMap document, JsonMap value) => addDeviceToDidDocument(
    document,
    rootKeyId,
    _entry(value),
    _map(value['signing_verification_method']),
    _map(value['e2ee_verification_method']),
    List<String>.from(fixture['retired_device_ids']! as List),
  );

  JsonMap update(JsonMap document, JsonMap value) => updateDeviceInDidDocument(
    document,
    rootKeyId,
    _entry(value),
    _map(value['signing_verification_method']),
    _map(value['e2ee_verification_method']),
  );

  group('P6 profile write contract', () {
    const validBundles = {
      'current P6': _currentP6,
      'current P6 with explicit base.v1': [..._currentP6, 'anp.group.base.v1'],
      'unchanged P5': [
        'anp.core.binding.v1',
        'anp.identity.discovery.v1',
        'anp.direct.base.v1',
        'anp.direct.e2ee.v2',
      ],
      'ordinary Base v1': [
        'anp.core.binding.v1',
        'anp.identity.discovery.v1',
        'anp.group.base.v1',
      ],
      'ordinary Base v2': [
        'anp.core.binding.v1',
        'anp.identity.discovery.v1',
        'anp.group.base.v2',
      ],
    };
    for (final bundle in validBundles.entries) {
      test('publishes ${bundle.key} without changing its capabilities', () {
        final input = device('device_a', bundle.value);
        final before = _clone(input);
        final document = build(input);
        expect(
          validateDeviceManifest(document)!.devices.single.profiles,
          equals(bundle.value),
        );
        if (bundle.value.contains('anp.group.e2ee.v2')) {
          expect(
            findEligibleDevice(
              document,
              _entry(input).deviceId,
              'anp.group.e2ee.v2',
            ),
            isNotNull,
          );
        }
        expect(input, equals(before));
      });
    }

    for (final missing in _currentP6.take(3)) {
      test('rejects current P6 missing $missing', () {
        final profiles = _currentP6.where((p) => p != missing).toList();
        expect(
          () => build(device('device_a', profiles)),
          throwsA(isA<AnpAuthenticationException>()),
        );
      });
    }

    for (final missing in const [
      'anp.core.binding.v1',
      'anp.identity.discovery.v1',
    ]) {
      test('rejects ordinary Base v2 missing $missing', () {
        final profiles = _currentP6
            .where((p) => p != 'anp.group.e2ee.v2' && p != missing)
            .toList();
        expect(
          () => build(device('device_a', profiles)),
          throwsA(isA<AnpAuthenticationException>()),
        );
      });
    }

    const legacyBundles = {
      'legacy mixed': [
        'anp.core.binding.v1',
        'anp.identity.discovery.v1',
        'anp.group.base.v1',
        'anp.group.e2ee.v2',
      ],
      'legacy all-v2': [
        'anp.core.binding.v2',
        'anp.identity.discovery.v2',
        'anp.group.base.v2',
        'anp.group.e2ee.v2',
      ],
    };
    for (final bundle in legacyBundles.entries) {
      test('reads ${bundle.key} and requires canonical mutation results', () {
        final current = build(device('device_a'));
        final currentBefore = _clone(current);
        final legacyA = device('device_a', bundle.value);
        final legacyB = device('device_b', bundle.value);
        final legacyBefore = _clone(legacyA);
        final legacyDocument = _clone(current);
        final manifest = _map(legacyDocument['deviceManifest']);
        final entries = List<Object?>.from(manifest['devices']! as List);
        final directBase = bundle.value.contains('anp.core.binding.v2')
            ? 'anp.direct.base.v2'
            : 'anp.direct.base.v1';
        entries[0] = _map(entries[0])
          ..['profiles'] = [...bundle.value, directBase, 'anp.direct.e2ee.v2'];
        legacyDocument['deviceManifest'] = manifest..['devices'] = entries;
        legacyDocument['proof'] = {'proofValue': 'preserve-on-rejection'};
        final documentBefore = _clone(legacyDocument);
        final deviceId = _entry(legacyA).deviceId;

        expect(validateDeviceManifest(legacyDocument), isNotNull);
        expect(
          findEligibleDevice(legacyDocument, deviceId, 'anp.group.e2ee.v2'),
          isNull,
        );
        expect(
          findEligibleDevice(legacyDocument, deviceId, 'anp.direct.e2ee.v2'),
          isNotNull,
        );
        final writes = <JsonMap Function()>[
          () => build(legacyA),
          () => add(current, legacyB),
          () => update(current, legacyA),
          () => add(legacyDocument, device('device_b')),
        ];
        for (final write in writes) {
          expect(write, throwsA(isA<AnpAuthenticationException>()));
        }
        expect(update(legacyDocument, device('device_a')), equals(current));
        final mixedDocument = add(current, device('device_b'));
        final mixedManifest = _map(mixedDocument['deviceManifest']);
        final mixedEntries = List<Object?>.from(
          mixedManifest['devices']! as List,
        );
        mixedEntries[1] = _map(mixedEntries[1])
          ..['profiles'] = List.of(bundle.value);
        mixedDocument['deviceManifest'] = mixedManifest
          ..['devices'] = mixedEntries;
        mixedDocument['proof'] = {'proofValue': 'preserve-input-proof'};
        final mixedBefore = _clone(mixedDocument);
        expect(
          removeDeviceFromDidDocument(
            mixedDocument,
            rootKeyId,
            _entry(legacyB).deviceId,
          ),
          equals(current),
        );
        // Unrelated mutations must not republish a remaining historical entry.
        expect(
          () => update(mixedDocument, device('device_a')),
          throwsA(isA<AnpAuthenticationException>()),
        );
        expect(
          () => removeDeviceFromDidDocument(mixedDocument, rootKeyId, deviceId),
          throwsA(isA<AnpAuthenticationException>()),
        );
        expect(mixedDocument, equals(mixedBefore));
        expect(current, equals(currentBefore));
        expect(legacyDocument, equals(documentBefore));
        expect(legacyA, equals(legacyBefore));
      });
    }
  });
}

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
