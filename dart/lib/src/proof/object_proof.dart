import '../authentication/types.dart';
import '../codec/base58.dart';
import '../errors.dart';
import '../keys/key_material.dart';
import 'w3c_proof.dart';

const String objectProofPurpose = 'assertionMethod';

/// Generates the strict Appendix-B Object Proof used by P4/P5/P6 objects.
///
/// Object Proofs intentionally use base58-btc multibase (`z...`) for the
/// Ed25519 signature. This is distinct from the legacy generic W3C proof
/// helper, whose historical Dart wire encoding is base64url.
Future<JsonMap> generateObjectProof(
  JsonMap document,
  MessageSigner signer,
  String verificationMethod, {
  DateTime? created,
}) async {
  if (signer.keyType != KeyType.ed25519) {
    throw const AnpProofException(
      'Appendix-B object proof requires an Ed25519 signing key',
    );
  }
  _validateVerificationMethod(verificationMethod);
  if (signer.keyId != verificationMethod) {
    throw const AnpProofException(
      'object proof signer does not match verificationMethod',
    );
  }

  final proofOptions = <String, Object?>{
    'type': proofTypeDataIntegrity,
    'cryptosuite': cryptosuiteEddsaJcs2022,
    'verificationMethod': verificationMethod,
    'proofPurpose': objectProofPurpose,
    'created': _isoSeconds(created ?? DateTime.now().toUtc()),
  };
  final unsigned = Map<String, Object?>.from(document)..remove('proof');
  final signature = await signer.sign(
    computeW3cProofSigningInput(unsigned, proofOptions),
  );
  if (signature.length != 64) {
    throw const AnpProofException(
      'Appendix-B object proof requires a 64-byte Ed25519 signature',
    );
  }
  return {
    ...unsigned,
    'proof': {...proofOptions, 'proofValue': 'z${encodeBase58(signature)}'},
  };
}

/// Verifies the cryptographic portion of a strict Appendix-B Object Proof.
///
/// The owning Profile remains responsible for issuer-DID ownership,
/// assertionMethod authorization, Manifest binding, and object-state checks.
Future<bool> verifyObjectProof(
  JsonMap document,
  MessageVerifier verifier,
) async {
  try {
    final rawProof = document['proof'];
    if (rawProof is! Map) return false;
    final proof = Map<String, Object?>.from(rawProof.cast<String, Object?>());
    for (final field in const [
      'type',
      'cryptosuite',
      'verificationMethod',
      'proofPurpose',
      'created',
      'proofValue',
    ]) {
      final value = proof[field];
      if (value is! String || value.isEmpty) return false;
    }
    if (proof['type'] != proofTypeDataIntegrity ||
        proof['cryptosuite'] != cryptosuiteEddsaJcs2022 ||
        proof['proofPurpose'] != objectProofPurpose) {
      return false;
    }

    final verificationMethod = proof['verificationMethod']! as String;
    _validateVerificationMethod(verificationMethod);
    if (verifier.keyTypeFor(verificationMethod) != KeyType.ed25519) {
      return false;
    }
    if (!_isRfc3339(proof['created']! as String)) return false;

    final proofValue = proof.remove('proofValue')! as String;
    if (!proofValue.startsWith('z') || proofValue.length == 1) return false;
    final signature = decodeBase58(proofValue.substring(1));
    if (signature.length != 64) return false;

    final unsigned = Map<String, Object?>.from(document)..remove('proof');
    return verifier.verify(
      computeW3cProofSigningInput(unsigned, proof),
      signature,
      verificationMethod,
    );
  } catch (_) {
    return false;
  }
}

void _validateVerificationMethod(String value) {
  final separator = value.indexOf('#');
  if (!value.startsWith('did:') ||
      separator <= 4 ||
      separator == value.length - 1) {
    throw const AnpProofException('verificationMethod must be a full DID URL');
  }
}

bool _isRfc3339(String value) {
  if (!value.contains('T') ||
      !(value.endsWith('Z') || RegExp(r'[+-]\d{2}:\d{2}$').hasMatch(value))) {
    return false;
  }
  return DateTime.tryParse(value) != null;
}

String _isoSeconds(DateTime value) =>
    value.toUtc().toIso8601String().replaceFirst(RegExp(r'\.\d+Z$'), 'Z');
