import '../authentication/types.dart';
import 'proof.dart';

Future<JsonMap> generateObjectProof(
  JsonMap document,
  MessageSigner signer,
  String verificationMethod,
) => generateW3cProof(document, signer, verificationMethod);

Future<bool> verifyObjectProof(JsonMap document, MessageVerifier verifier) =>
    verifyW3cProof(document, verifier);
