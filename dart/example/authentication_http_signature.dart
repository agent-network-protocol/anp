import 'package:anp/anp.dart';

Future<void> main() async {
  final key = generatePrivateKeyMaterial(KeyType.ed25519);
  final signer = PrivateKeyMessageSigner(
    keyId: 'did:wba:example.com#key-1',
    privateKey: key,
  );
  final verifier = PublicKeyMessageVerifier({signer.keyId: key.publicKey()});
  final body = '{"item":"book"}'.codeUnits;
  final headers = await generateHttpSignatureHeaders(
    'POST',
    'https://api.example.com/orders',
    signer,
    body,
  );
  final ok = await verifyHttpMessageSignature(
    'POST',
    'https://api.example.com/orders',
    verifier,
    headers,
    body,
  );
  print(ok);
}
