import '../authentication/types.dart';
import 'proof.dart';

Future<JsonMap> generateDidWbaBinding({
  required String agentDid,
  required String leafSignatureKey,
  required MessageSigner signer,
}) => generateW3cProof(
  {'agent_did': agentDid, 'leaf_signature_key': leafSignatureKey},
  signer,
  signer.keyId,
);

Future<bool> verifyDidWbaBinding(JsonMap binding, MessageVerifier verifier) =>
    verifyW3cProof(binding, verifier);
