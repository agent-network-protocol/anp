import '../authentication/types.dart';
import 'proof.dart';

const String groupReceiptProofPurpose = 'assertionMethod';

Future<JsonMap> generateGroupReceiptProof(
  JsonMap receipt,
  MessageSigner signer,
  String verificationMethod,
) => generateW3cProof(
  receipt,
  signer,
  verificationMethod,
  options: const ProofGenerationOptions(proofPurpose: groupReceiptProofPurpose),
);

Future<bool> verifyGroupReceiptProof(
  JsonMap receipt,
  MessageVerifier verifier,
) => verifyW3cProof(
  receipt,
  verifier,
  options: const ProofVerificationOptions(
    expectedProofPurpose: groupReceiptProofPurpose,
  ),
);
