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

  test('http signature headers verify through injected verifier', () async {
    final key = generatePrivateKeyMaterial(KeyType.ed25519);
    final signer = PrivateKeyMessageSigner(
      keyId: 'did:wba:example.com#key-1',
      privateKey: key,
    );
    final verifier = PublicKeyMessageVerifier({signer.keyId: key.publicKey()});
    final body = [1, 2, 3];
    final headers = await generateHttpSignatureHeaders(
      'POST',
      'https://example.com/rpc',
      signer,
      body,
    );
    expect(
      await verifyHttpMessageSignature(
        'POST',
        'https://example.com/rpc',
        verifier,
        headers,
        body,
      ),
      isTrue,
    );
  });
}
