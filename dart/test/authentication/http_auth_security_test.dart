import 'dart:convert';
import 'dart:io';
import 'package:anp/anp.dart';
import 'package:test/test.dart';

class UnavailableStore implements HttpReplayStore {
  @override
  Future<bool> consumeOnce(HttpReplayContext context) async =>
      throw StateError('unit unavailable');
}

void main() {
  final corpus =
      jsonDecode(
            File(
              '../testdata/authentication/security_vectors_v1.json',
            ).readAsStringSync(),
          )
          as Map<String, Object?>;
  final now = corpus['now'] as int;
  final document = Map<String, Object?>.from(corpus['document'] as Map);
  final cases = (corpus['cases'] as List)
      .map((item) => Map<String, Object?>.from(item as Map))
      .toList();
  Map<String, String> headers(Map<String, Object?> vector) =>
      Map<String, String>.from(vector['headers'] as Map);
  for (final vector in cases) {
    test('shared HTTP security vector ${vector['id']}', () async {
      final operation = verifyHttpMessageSignature(
        didDocument: document,
        requestMethod: vector['method'] as String,
        requestUrl: vector['url'] as String,
        headers: headers(vector),
        body: utf8.encode(vector['body'] as String),
        now: now,
      );
      if (vector['accepted'] == true) {
        await expectLater(operation, completes);
      } else {
        await expectLater(operation, throwsA(anything));
      }
    });
  }

  test(
    'frozen authority compatibility retains exact target and common replay key',
    () async {
      final corpus =
          jsonDecode(
                File(
                  '../testdata/authentication/authority_compatibility_v1.json',
                ).readAsStringSync(),
              )
              as Map;
      final doc = Map<String, Object?>.from(corpus['document'] as Map);
      for (final raw in corpus['cases'] as List) {
        final v = raw as Map,
            url = v['url'] as String,
            headers = Map<String, String>.from(v['headers'] as Map);
        final metadata = await verifyHttpMessageSignature(
          didDocument: doc,
          body: const [],
          requestMethod: 'GET',
          requestUrl: url,
          headers: headers,
          now: corpus['now'] as int,
        ).catchError((Object error) => throw StateError("${v['id']}: $error"));
        expect(
          httpSignatureReplayContext(metadata, 'GET', url, headers).replayKey,
          v['replay_key'],
        );
        await expectLater(
          verifyHttpMessageSignature(
            didDocument: doc,
            body: const [],
            requestMethod: 'GET',
            requestUrl: '${url}tampered',
            headers: headers,
            now: corpus['now'] as int,
          ),
          throwsA(anything),
        );
      }
    },
  );

  test('bounded fields and duplicate-free Legacy parsing', () async {
    final legacy =
        jsonDecode(
              File(
                '../testdata/authentication/legacy_compatibility_v1.json',
              ).readAsStringSync(),
            )
            as Map;
    final header = legacy['header'] as String;
    expect(extractAuthHeaderParts(header).nonce, 'public-legacy-fixture');
    for (final tail in [
      ', nonce="duplicate"',
      ', DID="duplicate"',
      ', v="1.0"',
      ' garbage',
    ]) {
      expect(() => extractAuthHeaderParts(header + tail), throwsA(anything));
    }
    final v = cases.first;
    for (final value in [
      "sig1=:${'A' * 20000}:",
      '${headers(v)['Signature']}\r\nInjected: value',
    ]) {
      await expectLater(
        verifyHttpMessageSignature(
          didDocument: document,
          requestMethod: 'GET',
          requestUrl: v['url'] as String,
          headers: {...headers(v), 'Signature': value},
          body: [],
          now: now,
        ),
        throwsA(anything),
      );
    }
  });

  test('IPv6 origins normalize the same host and reject mapped aliases', () {
    expect(
      authenticationOrigin(
        'https://[2001:4860:0000:0000:0000:0000:0000:8888]/',
      ),
      'https://[2001:4860::8888]:443',
    );
    expect(
      () => authenticationOrigin('https://[::ffff:8.8.8.8]/'),
      throwsA(anything),
    );
  });
  test(
    'historical verification requires explicit frozen clock or crypto-only mode',
    () async {
      final v = cases[2];
      await expectLater(
        verifyHttpMessageSignature(
          didDocument: document,
          requestMethod: 'GET',
          requestUrl: v['url'] as String,
          headers: headers(v),
          body: [],
        ),
        throwsA(anything),
      );
      await expectLater(
        verifyHttpMessageSignature(
          didDocument: document,
          requestMethod: 'GET',
          requestUrl: v['url'] as String,
          headers: headers(v),
          body: [],
          policy: const HttpSignaturePolicy(cryptoOnly: true),
        ),
        completes,
      );
    },
  );
  test(
    'duplicate params/headers and unsigned extensions fail closed',
    () async {
      final v = cases.first, original = headers(cases.first);
      for (final change in <Map<String, String>>[
        {'signature-input': original['Signature-Input']!},
        {'Signature-Input': '${original['Signature-Input']};created=1'},
        {'Signature-Input': '${original['Signature-Input']};tag="not-signed"'},
      ]) {
        await expectLater(
          verifyHttpMessageSignature(
            didDocument: document,
            requestMethod: 'GET',
            requestUrl: v['url'] as String,
            headers: {...original, ...change},
            body: [],
            now: now,
          ),
          throwsA(anything),
        );
      }
    },
  );
  test(
    'bounded memory replay store is atomic within an isolate and retains deadline',
    () async {
      var time = now;
      final store = MemoryHttpReplayStore(capacity: 1, clock: () => time);
      final context = HttpReplayContext(
        signerDid: 'did:web:unit.example',
        verifierScope: 'receiver',
        replayKey: 'key',
        validUntil: now + 60,
      );
      final results = await Future.wait(
        List.generate(
          20,
          (_) => Future<bool>(() => store.consumeOnce(context)),
        ),
      );
      expect(results.where((value) => value), hasLength(1));
      time += 60;
      expect(store.consumeOnce(context), isFalse);
      final other = HttpReplayContext(
        signerDid: context.signerDid,
        verifierScope: context.verifierScope,
        replayKey: 'other',
        validUntil: now + 120,
      );
      expect(() => store.consumeOnce(other), throwsA(anything));
      time++;
      expect(store.consumeOnce(other), isTrue);
    },
  );
  test(
    'caller DID cannot substitute the verified identity and no-nonce requests are replay protected',
    () async {
      final v = cases[1], store = MemoryHttpReplayStore(clock: () => now);
      DidWbaVerifier make() => DidWbaVerifier(
        didDocument: document,
        replayStore: store,
        clock: () => now,
      );
      final first = make(), second = make();
      await expectLater(
        first.verifyRequest(
          'GET',
          v['url'] as String,
          headers(v),
          [],
          'did:web:other.example',
        ),
        throwsA(anything),
      );
      final result = await first.verifyRequest(
        'GET',
        v['url'] as String,
        headers(v),
        [],
        document['id'] as String,
      );
      expect(result.did, document['id']);
      await expectLater(
        second.verifyRequest(
          'GET',
          v['url'] as String,
          headers(v),
          [],
          document['id'] as String,
        ),
        throwsA(anything),
      );
      final unavailable = DidWbaVerifier(
        didDocument: document,
        replayStore: UnavailableStore(),
        clock: () => now,
      );
      await expectLater(
        unavailable.verifyRequest(
          'GET',
          v['url'] as String,
          headers(v),
          [],
          document['id'] as String,
        ),
        throwsA(
          isA<AnpAuthenticationException>().having(
            (e) => e.message,
            'message',
            contains('unavailable'),
          ),
        ),
      );
    },
  );
  test(
    'Dart sender-only federation can no longer claim verification',
    () async {
      final result = await verifyFederatedHttpRequest(
        senderDid: 'did:wba:victim.example',
      );
      expect(result.verified, isFalse);
      expect(result.did, isNull);
    },
  );
  test(
    'federation authenticates serviceDid and consumes shared replay state',
    () async {
      final v = cases.first, store = MemoryHttpReplayStore(clock: () => now);
      final sender = <String, Object?>{
        'id': 'did:web:sender.example:agent',
        'service': [
          <String, Object?>{
            'id': 'message',
            'type': anpMessageServiceType,
            'serviceDid': document['id'],
            'serviceEndpoint': 'https://receiver.example/rpc',
          },
        ],
      };
      Future<FederatedVerificationResult> operation() =>
          verifyFederatedHttpRequest(
            senderDid: sender['id'] as String,
            requestMethod: 'GET',
            requestUrl: v['url'] as String,
            headers: headers(v),
            senderDidDocument: sender,
            serviceDidDocument: document,
            clock: () => now,
            replayStore: store,
          );
      final first = await operation();
      expect(first.verified, isTrue);
      expect(first.serviceDid, document['id']);
      expect((await operation()).verified, isFalse);
    },
  );
  test(
    'E1 fingerprint, root proof and assertion authorization are actually checked',
    () {
      final bundle = createDidWbaDocument(
        'example.com',
        options: const DidDocumentOptions(
          pathSegments: ['user', 'unit'],
          enableE2ee: false,
        ),
      );
      expect(validateDidDocumentBinding(bundle.didDocument), isTrue);
      final missingAssertion = Map<String, Object?>.from(bundle.didDocument)
        ..['assertionMethod'] = <String>[];
      expect(validateDidDocumentBinding(missingAssertion), isFalse);
      final tampered = Map<String, Object?>.from(bundle.didDocument)
        ..['service'] = <String>[];
      expect(validateDidDocumentBinding(tampered), isFalse);
      final unbound = Map<String, Object?>.from(bundle.didDocument)
        ..['id'] = '${bundle.did}x';
      expect(validateDidDocumentBinding(unbound), isFalse);
    },
  );
  test(
    'resource and origin parsing do not silently authorize ambiguous targets',
    () {
      expect(
        authenticationOrigin('https://EXAMPLE.com/a'),
        authenticationOrigin('https://example.com:443/b'),
      );
      expect(
        authenticationOrigin('https://example.com:8443/a'),
        isNot(authenticationOrigin('https://example.com/a')),
      );
      for (final did in [
        'did:wba:example.com%2fother:user',
        'did:wba:user%40example.com:alice',
        'did:web:example.com:..',
        'did:wba:example.com:%2fetc',
      ]) {
        expect(() => buildDidResolutionUrl(did), throwsA(anything));
      }
      expect(secureAuthNonceBytes(), hasLength(16));
    },
  );
  test(
    'Legacy realm/time/key checks precede nonce consumption and preserve valid requests',
    () async {
      final bundle = createDidWbaDocument(
        'identity.example',
        options: const DidDocumentOptions(
          pathSegments: ['user', 'legacy'],
          didProfile: DidProfile.k1,
          enableE2ee: false,
        ),
      );
      final store = MemoryHttpReplayStore(clock: () => now);
      final verifier = DidWbaVerifier(
        didDocument: bundle.didDocument,
        replayStore: store,
        clock: () => now,
      );
      final timestamp = DateTime.fromMillisecondsSinceEpoch(
        now * 1000,
        isUtc: true,
      ).toIso8601String();
      final header = await generateAuthHeader(
        bundle.didDocument,
        'receiver.example',
        bundle.keys[vmKeyAuth]!.privateKey,
        nonce: 'legacy-unit',
        timestamp: timestamp,
      );
      final invalid = header.replaceFirst(
        RegExp(r'signature="[^"]+"'),
        'signature="AA"',
      );
      await expectLater(
        verifier.verifyRequest(
          'GET',
          'https://receiver.example/rpc',
          {'Authorization': invalid},
          [],
          bundle.did,
        ),
        throwsA(anything),
      );
      await expectLater(
        verifier.verifyRequest(
          'GET',
          'https://other.example/rpc',
          {'Authorization': header},
          [],
          bundle.did,
        ),
        throwsA(anything),
      );
      expect(
        (await verifier.verifyRequest(
          'GET',
          'https://receiver.example/rpc',
          {'Authorization': header},
          [],
          bundle.did,
        )).did,
        bundle.did,
      );
      await expectLater(
        verifier.verifyRequest(
          'GET',
          'https://receiver.example/rpc',
          {'Authorization': header},
          [],
          bundle.did,
        ),
        throwsA(anything),
      );
      final old = await generateAuthHeader(
        bundle.didDocument,
        'receiver.example',
        bundle.keys[vmKeyAuth]!.privateKey,
        nonce: 'legacy-old-unit',
        timestamp: DateTime.fromMillisecondsSinceEpoch(
          (now - 600) * 1000,
          isUtc: true,
        ).toIso8601String(),
      );
      await expectLater(
        verifier.verifyRequest(
          'GET',
          'https://receiver.example/rpc',
          {'Authorization': old},
          [],
          bundle.did,
        ),
        throwsA(anything),
      );
    },
  );
}
