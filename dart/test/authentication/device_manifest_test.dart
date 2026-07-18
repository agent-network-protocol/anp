import 'dart:convert';
import 'dart:io';

import 'package:anp/anp.dart';
import 'package:test/test.dart';

void main() {
  final fixtures = _loadFixtures();

  group('shared Device Manifest fixtures', () {
    for (final rawCase in fixtures['valid']! as List<Object?>) {
      final testCase = _jsonMap(rawCase);
      test(testCase['name']! as String, () {
        final document = _buildDocument(fixtures, testCase);
        final before = jsonEncode(document);

        final parsed = parseDeviceManifest(document);
        expect(parsed, isNotNull);
        expect(parsed!.toJson(), equals(testCase['device_manifest']));
        expect(validateDeviceManifest(document)!.toJson(), parsed.toJson());

        final lookup = _jsonMap(testCase['lookup']);
        final device = findEligibleDevice(
          document,
          lookup['device_id']! as String,
          lookup['profile']! as String,
        );
        expect(device != null, lookup['found']);
        expect(jsonEncode(document), before);
        final extension = _jsonMap(document['x-fixture-extension']);
        expect(extension['must_survive_validation'], isTrue);
      });
    }

    for (final rawCase in fixtures['invalid']! as List<Object?>) {
      final testCase = _jsonMap(rawCase);
      test('rejects ${testCase['name']}', () {
        final document = _buildDocument(fixtures, testCase);
        expect(
          () => validateDeviceManifest(document),
          throwsA(isA<AnpAuthenticationException>()),
        );
      });
    }
  });

  test('Manifest absence does not create a default device', () {
    final document = _cloneMap(fixtures['base_did_document']);
    expect(parseDeviceManifest(document), isNull);
    expect(validateDeviceManifest(document), isNull);
    expect(
      findEligibleDevice(document, 'dev-a-7N3KQ2', profileDirectE2eeV2),
      isNull,
    );
  });
}

JsonMap _loadFixtures() {
  final path = File(
    '../testdata/device_manifest/vnext_device_manifest_fixtures.json',
  ).absolute;
  return _jsonMap(jsonDecode(path.readAsStringSync()));
}

JsonMap _buildDocument(JsonMap fixtures, JsonMap testCase) {
  final document = _cloneMap(fixtures['base_did_document']);
  final patch = testCase['document_patch'];
  if (patch != null) {
    document.addAll(_cloneMap(patch));
  }
  document['deviceManifest'] = _cloneValue(testCase['device_manifest']);
  return document;
}

JsonMap _cloneMap(Object? value) => _jsonMap(_cloneValue(value));

Object? _cloneValue(Object? value) => jsonDecode(jsonEncode(value));

JsonMap _jsonMap(Object? value) => Map<String, Object?>.from(
  (value! as Map<Object?, Object?>).cast<String, Object?>(),
);
