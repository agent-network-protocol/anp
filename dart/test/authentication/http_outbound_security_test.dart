import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';
import 'package:anp/anp.dart';
import 'package:anp/src/authentication/outbound.dart';
import 'package:anp/src/authentication/outbound_io.dart' as native;
import 'package:anp/src/authentication/outbound_policy.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:test/test.dart';

class FakeSocket implements Socket {
  @override
  dynamic noSuchMethod(Invocation invocation) => super.noSuchMethod(invocation);
}

class OpaqueSigner implements MessageSigner {
  OpaqueSigner(this.privateKey, this.keyId);
  final PrivateKeyMaterial privateKey;
  @override
  final String keyId;
  @override
  KeyType get keyType => privateKey.type;
  @override
  Future<Uint8List> sign(List<int> message) async => privateKey.sign(message);
}

void main() {
  test(
    'private literal targets fail before a custom transport can send',
    () async {
      var calls = 0;
      final client = MockClient((request) async {
        calls++;
        return http.Response('{}', 200);
      });
      addTearDown(client.close);
      for (final url in [
        'http://example.com/',
        'https://127.0.0.1/',
        'https://169.254.169.254/',
        'https://[::1]/',
        'https://[::ffff:127.0.0.1]/',
        'https://localhost./',
        'https://user@example.com/',
      ]) {
        await expectLater(
          publicDocumentGet(url, client: client),
          throwsA(anything),
        );
      }
      expect(calls, 0);
      expect(
        () => validatePublicUri(
          'http://127.0.0.1/root/did.json',
          baseUrlOverride: 'http://127.0.0.1/root',
        ),
        returnsNormally,
      );
      expect(
        () => validatePublicUri(
          'http://127.0.0.2/root/did.json',
          baseUrlOverride: 'http://127.0.0.1/root',
        ),
        throwsA(anything),
      );
      expect(
        () => validatePublicUri(
          'http://127.0.0.1/other/did.json',
          baseUrlOverride: 'http://127.0.0.1/root',
        ),
        throwsA(anything),
      );
    },
  );
  test(
    'IO resolver validates all DNS answers then gives connector a checked address',
    () async {
      var calls = 0;
      final socket = FakeSocket();
      Future<ConnectionTask<Socket>> dial(
        InternetAddress address,
        int port,
      ) async {
        calls++;
        expect(address.address, '8.8.8.8');
        expect(port, 443);
        return ConnectionTask.fromSocket(Future<Socket>.value(socket), () {});
      }

      final uri = Uri.parse('https://public.example/');
      await expectLater(
        native.connectChecked(
          uri,
          const Duration(seconds: 1),
          lookup: (_) async => [
            InternetAddress('8.8.8.8'),
            InternetAddress('10.0.0.1'),
          ],
          connectSocket: dial,
        ),
        throwsA(anything),
      );
      expect(calls, 0);
      final task = await native.connectChecked(
        uri,
        const Duration(seconds: 1),
        lookup: (_) async => [InternetAddress('8.8.8.8')],
        connectSocket: dial,
      );
      expect(await task.socket, same(socket));
      expect(calls, 1);
    },
  );
  test(
    'redirects are not followed and decoded bodies have a finite budget',
    () async {
      var calls = 0;
      final client = MockClient((request) async {
        calls++;
        expect(request.followRedirects, isFalse);
        return http.Response(
          'ignored',
          302,
          headers: {'Location': 'https://127.0.0.1/'},
        );
      });
      addTearDown(client.close);
      expect(
        (await publicDocumentGet(
          'https://public.example/',
          client: client,
        )).statusCode,
        302,
      );
      expect(calls, 1);
      final large = MockClient.streaming(
        (request, body) async => http.StreamedResponse(
          Stream<List<int>>.fromIterable([
            List<int>.filled(maxDocumentBytes + 1, 32),
          ]),
          200,
        ),
      );
      addTearDown(large.close);
      await expectLater(
        publicDocumentGet('https://public.example/', client: large),
        throwsA(anything),
      );
    },
  );
  test(
    'WBA and native Web resolve the correct resource and enforce exact document id',
    () async {
      final calls = <String>[];
      var did = 'did:web:identity.example:users:e1_not-a-wba-root';
      final client = MockClient((request) async {
        calls.add(request.url.path);
        return http.Response(
          jsonEncode({
            'id': did,
            'verificationMethod': <Object?>[],
            'authentication': <String>[],
          }),
          200,
          headers: {'Content-Type': 'application/json'},
        );
      });
      addTearDown(client.close);
      final web = await resolveDidDocument(did, client: client);
      expect(web['id'], did);
      did = 'did:web:other.example';
      await expectLater(
        resolveDidDocument('did:web:identity.example', client: client),
        throwsA(anything),
      );
      final bundle = createDidWbaDocument(
        'identity.example',
        options: const DidDocumentOptions(enableE2ee: false),
      );
      final wba = MockClient((request) async {
        calls.add(request.url.path);
        return http.Response(
          jsonEncode(bundle.didDocument),
          200,
          headers: {'Content-Type': 'application/json'},
        );
      });
      addTearDown(wba.close);
      expect(
        (await resolveDidWbaDocument(bundle.did, client: wba))['id'],
        bundle.did,
      );
      expect(calls.last, '/.well-known/did.json');
    },
  );
  test(
    'sender accepts an opaque signer without reading a private-key property',
    () async {
      final bundle = createDidWbaDocument(
        'identity.example',
        options: const DidDocumentOptions(enableE2ee: false),
      );
      final signer = OpaqueSigner(
        bundle.keys[vmKeyAuth]!.privateKey,
        '${bundle.did}#key-1',
      );
      final helper = DidWbaAuthenticator(signer: signer);
      final headers = await helper.getAuthHeaders(
        'GET',
        'https://receiver.example/rpc',
        [],
      );
      expect(
        (await verifyHttpMessageSignature(
          didDocument: bundle.didDocument,
          requestMethod: 'GET',
          requestUrl: 'https://receiver.example/rpc',
          headers: headers,
          body: [],
        )).keyId,
        signer.keyId,
      );
    },
  );
  test(
    'WNS status semantics remain moved/not-found/gone with no real backend',
    () async {
      for (final code in [301, 404, 410]) {
        var calls = 0;
        final client = MockClient((request) async {
          calls++;
          expect(request.followRedirects, isFalse);
          return http.Response('', code);
        });
        try {
          await expectLater(
            resolveHandle('alice.example.com', client: client),
            throwsA(isA<AnpWnsException>()),
          );
          expect(calls, 1);
        } finally {
          client.close();
        }
      }
    },
  );
}
