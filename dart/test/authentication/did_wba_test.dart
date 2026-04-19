import 'package:anp/anp.dart';
import 'package:test/test.dart';

void main() {
  test('creates DID WBA document', () {
    final bundle = createDidWbaDocument(
      'example.com',
      options: const DidDocumentOptions(pathSegments: ['user', 'alice']),
    );
    expect(bundle.did, 'did:wba:example.com:user:alice');
    expect(validateDidDocumentBinding(bundle.didDocument), isTrue);
    expect(bundle.keys, contains(vmKeyAuth));
  });

  test('http signature headers verify through DID document', () async {
    final bundle = createDidWbaDocument('example.com');
    final body = [1, 2, 3];
    final headers = await generateHttpSignatureHeaders(
      didDocument: bundle.didDocument,
      requestMethod: 'POST',
      requestUrl: 'https://example.com/rpc',
      privateKey: bundle.keys[vmKeyAuth]!.privateKey,
      body: body,
      options: const HttpSignatureOptions(
        createdSeconds: 1,
        expiresSeconds: 301,
        nonce: 'nonce',
      ),
    );
    final metadata = await verifyHttpMessageSignature(
      didDocument: bundle.didDocument,
      requestMethod: 'POST',
      requestUrl: 'https://example.com/rpc',
      headers: headers,
      body: body,
    );
    expect(metadata.keyId, '${bundle.did}#key-1');
  });

  test('legacy auth header and json verify', () async {
    final bundle = createDidWbaDocument('example.com');
    final privateKey = bundle.keys[vmKeyAuth]!.privateKey;
    final header = await generateAuthHeader(
      bundle.didDocument,
      'api.example.com',
      privateKey,
      nonce: 'nonce',
      timestamp: '2026-04-19T00:00:00Z',
    );
    await verifyAuthHeaderSignature(
      header,
      bundle.didDocument,
      'api.example.com',
    );
    final json = await generateAuthJson(
      bundle.didDocument,
      'api.example.com',
      privateKey,
      nonce: 'nonce',
      timestamp: '2026-04-19T00:00:00Z',
    );
    await verifyAuthJsonSignature(json, bundle.didDocument, 'api.example.com');
  });
}
