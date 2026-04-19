import 'package:anp/anp.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  test('ANP Dart SDK imports and runs in Flutter test environment', () async {
    final bundle = createDidWbaDocument(
      'example.com',
      options: const DidDocumentOptions(pathSegments: ['user', 'flutter']),
    );
    expect(bundle.did, startsWith('did:wba:example.com:user:flutter'));
    expect(validateDidDocumentBinding(bundle.didDocument), isTrue);

    final key = bundle.keys[vmKeyAuth]!.privateKey;
    final body = '{"item":"book"}'.codeUnits;
    final headers = await generateHttpSignatureHeaders(
      didDocument: bundle.didDocument,
      requestMethod: 'POST',
      requestUrl: 'https://api.example.com/orders',
      privateKey: key,
      body: body,
      options: const HttpSignatureOptions(
        createdSeconds: 1,
        expiresSeconds: 301,
        nonce: 'flutter-smoke',
      ),
    );
    final metadata = await verifyHttpMessageSignature(
      didDocument: bundle.didDocument,
      requestMethod: 'POST',
      requestUrl: 'https://api.example.com/orders',
      headers: headers,
      body: body,
    );
    expect(metadata.keyId, '${bundle.did}#$vmKeyAuth');

    final parsed = validateHandle('alice.example.com');
    expect(buildWbaUri(parsed.localPart, parsed.domain), 'wba://alice.example.com');
  });
}
