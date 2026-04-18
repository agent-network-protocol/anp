import '../authentication/types.dart';
import '../codec/base64.dart';
import '../codec/canonical_json.dart';
import '../errors.dart';

const String proofTypeDataIntegrity = 'DataIntegrityProof';
const String cryptosuiteEddsaJcs2022 = 'eddsa-jcs-2022';

class ProofGenerationOptions {
  const ProofGenerationOptions({
    this.type = proofTypeDataIntegrity,
    this.cryptosuite = cryptosuiteEddsaJcs2022,
    this.created,
    this.proofPurpose = 'assertionMethod',
  });
  final String type;
  final String cryptosuite;
  final DateTime? created;
  final String proofPurpose;
}

class ProofVerificationOptions {
  const ProofVerificationOptions({this.expectedProofPurpose});
  final String? expectedProofPurpose;
}

Future<JsonMap> generateW3cProof(
  JsonMap document,
  MessageSigner signer,
  String verificationMethod, {
  ProofGenerationOptions options = const ProofGenerationOptions(),
}) async {
  final proof = <String, Object?>{
    'type': options.type,
    'cryptosuite': options.cryptosuite,
    'created': (options.created ?? DateTime.now().toUtc()).toIso8601String(),
    'proofPurpose': options.proofPurpose,
    'verificationMethod': verificationMethod,
  };
  final signingInput = canonicalJsonBytes({...document, 'proof': proof});
  proof['proofValue'] = encodeBase64Url(await signer.sign(signingInput));
  return {...document, 'proof': proof};
}

Future<bool> verifyW3cProof(
  JsonMap document,
  MessageVerifier verifier, {
  ProofVerificationOptions options = const ProofVerificationOptions(),
}) async {
  try {
    await verifyW3cProofDetailed(document, verifier, options: options);
    return true;
  } on AnpProofException {
    return false;
  }
}

Future<void> verifyW3cProofDetailed(
  JsonMap document,
  MessageVerifier verifier, {
  ProofVerificationOptions options = const ProofVerificationOptions(),
}) async {
  final proof = document['proof'];
  if (proof is! Map) throw const AnpProofException('missing proof');
  final proofMap = Map<String, Object?>.from(proof.cast<String, Object?>());
  final proofValue = proofMap.remove('proofValue');
  final verificationMethod = proofMap['verificationMethod'];
  final proofPurpose = proofMap['proofPurpose'];
  if (proofValue is! String || verificationMethod is! String) {
    throw const AnpProofException('invalid proof');
  }
  if (options.expectedProofPurpose != null &&
      proofPurpose != options.expectedProofPurpose) {
    throw const AnpProofException('unexpected proof purpose');
  }
  final withoutProof = Map<String, Object?>.from(document)..remove('proof');
  final ok = await verifier.verify(
    canonicalJsonBytes({...withoutProof, 'proof': proofMap}),
    decodeBase64Url(proofValue),
    verificationMethod,
  );
  if (!ok) throw const AnpProofException('proof signature verification failed');
}
