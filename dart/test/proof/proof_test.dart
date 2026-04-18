import 'package:anp/anp.dart';
import 'package:test/test.dart';

void main() {
  test('generates and verifies W3C proof shape', () async {
    final key = generatePrivateKeyMaterial(KeyType.ed25519);
    final signer = PrivateKeyMessageSigner(
      keyId: 'did:wba:example.com#key-1',
      privateKey: key,
    );
    final verifier = PublicKeyMessageVerifier({signer.keyId: key.publicKey()});
    final signed = await generateW3cProof(
      {'id': 'doc-1'},
      signer,
      signer.keyId,
    );
    expect(signed['proof'], isA<Map<Object?, Object?>>());
    expect(await verifyW3cProof(signed, verifier), isTrue);
  });
}
