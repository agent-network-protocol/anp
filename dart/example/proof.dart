import 'package:anp/anp.dart';

Future<void> main() async {
  final key = generatePrivateKeyMaterial(KeyType.ed25519);
  final signer = PrivateKeyMessageSigner(
    keyId: 'did:wba:example.com#key-1',
    privateKey: key,
  );
  final verifier = PublicKeyMessageVerifier({signer.keyId: key.publicKey()});
  final document = <String, Object?>{'id': 'urn:example:1', 'name': 'demo'};
  final signed = await generateW3cProof(document, signer, signer.keyId);
  print(await verifyW3cProof(signed, verifier));
}
