import '../authentication/types.dart';
import '../codec/base64.dart';
import '../codec/canonical_json.dart';
import '../errors.dart';
import '../keys/key_material.dart';

const String proofTypeSecp256k1 = 'EcdsaSecp256k1Signature2019';
const String proofTypeEd25519 = 'Ed25519Signature2020';
const String proofTypeDataIntegrity = 'DataIntegrityProof';
const String cryptosuiteEddsaJcs2022 = 'eddsa-jcs-2022';
const String cryptosuiteDidWbaSecp256k12025 = 'didwba-jcs-ecdsa-secp256k1-2025';

class ProofGenerationOptions {
  const ProofGenerationOptions({
    this.type,
    this.cryptosuite,
    this.created,
    this.proofPurpose = 'assertionMethod',
    this.domain,
    this.challenge,
  });
  final String? type;
  final String? cryptosuite;
  final DateTime? created;
  final String proofPurpose;
  final String? domain;
  final String? challenge;
}

class ProofVerificationOptions {
  const ProofVerificationOptions({
    this.expectedProofPurpose,
    this.expectedDomain,
    this.expectedChallenge,
  });
  final String? expectedProofPurpose;
  final String? expectedDomain;
  final String? expectedChallenge;
}

Future<JsonMap> generateW3cProof(
  JsonMap document,
  MessageSigner signer,
  String verificationMethod, {
  ProofGenerationOptions options = const ProofGenerationOptions(),
}) async {
  final keyType = signer.keyType;
  final proofType = options.type ?? _inferProofType(keyType);
  final proof = <String, Object?>{
    'type': proofType,
    'created': _isoSeconds(options.created ?? DateTime.now().toUtc()),
    'verificationMethod': verificationMethod,
    'proofPurpose': options.proofPurpose,
  };
  if (proofType == proofTypeDataIntegrity) {
    proof['cryptosuite'] = options.cryptosuite ?? _inferCryptosuite(keyType);
  } else if (options.cryptosuite != null) {
    proof['cryptosuite'] = options.cryptosuite;
  }
  if (options.domain != null) proof['domain'] = options.domain;
  if (options.challenge != null) proof['challenge'] = options.challenge;

  final unsigned = Map<String, Object?>.from(document)..remove('proof');
  final signature = await signer.sign(_computeSigningInput(unsigned, proof));
  proof['proofValue'] = encodeBase64Url(signature);
  return {...unsigned, 'proof': proof};
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
  if (proof is! Map) throw const AnpProofException('missing proof object');
  final proofMap = Map<String, Object?>.from(proof.cast<String, Object?>());
  final proofValue = proofMap.remove('proofValue');
  final verificationMethod = proofMap['verificationMethod'];
  final proofPurpose = proofMap['proofPurpose'];
  final created = proofMap['created'];
  if (proofValue is! String ||
      verificationMethod is! String ||
      proofPurpose is! String ||
      created is! String) {
    throw const AnpProofException('invalid proof');
  }
  if (options.expectedProofPurpose != null &&
      proofPurpose != options.expectedProofPurpose) {
    throw const AnpProofException('verification failed');
  }
  if (options.expectedDomain != null &&
      proofMap['domain'] != options.expectedDomain) {
    throw const AnpProofException('verification failed');
  }
  if (options.expectedChallenge != null &&
      proofMap['challenge'] != options.expectedChallenge) {
    throw const AnpProofException('verification failed');
  }
  final unsigned = Map<String, Object?>.from(document)..remove('proof');
  final signature = decodeBase64Url(proofValue);
  final ok = await verifier.verify(
    _computeSigningInput(unsigned, proofMap),
    signature,
    verificationMethod,
  );
  if (!ok) throw const AnpProofException('verification failed');
}

List<int> computeW3cProofSigningInput(JsonMap document, JsonMap proofOptions) =>
    _computeSigningInput(document, proofOptions);

List<int> _computeSigningInput(JsonMap document, JsonMap proofOptions) {
  final documentHash = sha256Bytes(canonicalJsonBytes(document));
  final proofHash = sha256Bytes(canonicalJsonBytes(proofOptions));
  return [...proofHash, ...documentHash];
}

String _inferProofType(KeyType? keyType) => switch (keyType) {
  KeyType.secp256k1 => proofTypeSecp256k1,
  KeyType.ed25519 => proofTypeEd25519,
  _ => proofTypeDataIntegrity,
};

String _inferCryptosuite(KeyType? keyType) => switch (keyType) {
  KeyType.secp256k1 => cryptosuiteDidWbaSecp256k12025,
  KeyType.ed25519 => cryptosuiteEddsaJcs2022,
  _ => '',
};

String _isoSeconds(DateTime value) =>
    value.toUtc().toIso8601String().replaceFirst(RegExp(r'\.\d+Z$'), 'Z');
