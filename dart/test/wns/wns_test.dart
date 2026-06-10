import 'dart:convert';

import 'package:anp/anp.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:test/test.dart';

void main() {
  test('validates and builds WBA URI', () {
    final parsed = validateHandle('Alice.Example.COM');
    expect(parsed.handle, 'alice.example.com');
    expect(
      buildWbaUri(parsed.localPart, parsed.domain),
      'wba://alice.example.com',
    );
  });

  test('extracts handle service', () {
    final service = buildHandleServiceEntry(
      'did:wba:example.com:user:alice',
      'alice',
      'example.com',
    );
    final services = extractHandleServiceFromDidDocument({
      'service': [service.toJson()],
    });
    expect(services.single.type, anpHandleServiceType);
  });

  test('resolves handle with DID Subject Profile', () async {
    final client = MockClient((request) async {
      expect(request.url.path, '/.well-known/handle/alice');
      return http.Response(
        jsonEncode({
          'handle': 'alice.example.com',
          'did': 'did:wba:example.com:user:alice',
          'status': 'active',
          'updated': '2025-01-01T00:00:00Z',
          'versionId': '42',
          'ttl': 300,
          'profile': {
            'type': 'DIDSubjectProfile',
            'subject_did': 'did:wba:example.com:user:alice',
            'subject_type': 'person',
            'handle': 'alice.example.com',
            'display_name': 'Alice',
            'avatar_uri': 'https://example.com/avatars/alice.png',
            'proof': {'type': 'DataIntegrityProof'},
          },
        }),
        200,
        headers: {'content-type': 'application/json'},
      );
    });

    final document = await resolveHandle(
      'alice.example.com',
      options: const ResolveHandleOptions(
        baseUrlOverride: 'https://example.com',
      ),
      client: client,
    );

    expect(document.did, 'did:wba:example.com:user:alice');
    expect(document.status, HandleStatus.active);
    expect(document.versionId, '42');
    expect(document.ttl, 300);
    expect(document.profile?.subjectType, SubjectType.person);
    expect(document.profile?.displayName, 'Alice');
    expect(document.profile?.proof?['type'], 'DataIntegrityProof');
  });

  test('ignores profile subject DID mismatch during resolution', () async {
    final client = MockClient((request) async {
      return http.Response(
        jsonEncode({
          'handle': 'alice.example.com',
          'did': 'did:wba:example.com:user:alice',
          'status': 'active',
          'profile': {
            'subject_did': 'did:wba:example.com:user:bob',
            'display_name': 'Bob',
          },
        }),
        200,
        headers: {'content-type': 'application/json'},
      );
    });

    final document = await resolveHandle(
      'alice.example.com',
      options: const ResolveHandleOptions(
        baseUrlOverride: 'https://example.com',
      ),
      client: client,
    );

    expect(document.did, 'did:wba:example.com:user:alice');
    expect(document.profile, isNull);
  });

  test('ignores profile handle mismatch during resolution', () async {
    final client = MockClient((request) async {
      return http.Response(
        jsonEncode({
          'handle': 'alice.example.com',
          'did': 'did:wba:example.com:user:alice',
          'status': 'active',
          'profile': {
            'subject_did': 'did:wba:example.com:user:alice',
            'handle': 'bob.example.com',
            'display_name': 'Bob',
          },
        }),
        200,
        headers: {'content-type': 'application/json'},
      );
    });

    final document = await resolveHandle(
      'alice.example.com',
      options: const ResolveHandleOptions(
        baseUrlOverride: 'https://example.com',
      ),
      client: client,
    );

    expect(document.did, 'did:wba:example.com:user:alice');
    expect(document.profile, isNull);
  });

  test('normalizes unknown profile subject type to unknown', () async {
    final client = MockClient((request) async {
      return http.Response(
        jsonEncode({
          'handle': 'alice.example.com',
          'did': 'did:wba:example.com:user:alice',
          'status': 'active',
          'profile': {
            'subject_did': 'did:wba:example.com:user:alice',
            'subject_type': 'custom-private-type',
            'display_name': 'Alice',
          },
        }),
        200,
        headers: {'content-type': 'application/json'},
      );
    });

    final document = await resolveHandle(
      'alice.example.com',
      options: const ResolveHandleOptions(
        baseUrlOverride: 'https://example.com',
      ),
      client: client,
    );

    expect(document.profile?.subjectType, SubjectType.unknown);
  });
}
