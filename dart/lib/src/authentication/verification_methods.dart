import '../codec/base58.dart';
import '../keys/keys.dart';
import 'types.dart';

JsonMap? findVerificationMethod(
  JsonMap didDocument,
  String verificationMethodId,
) {
  final methods = didDocument['verificationMethod'];
  if (methods is! List) return null;
  for (final method in methods) {
    if (method is Map && method['id'] == verificationMethodId) {
      return Map<String, Object?>.from(method.cast<String, Object?>());
    }
  }
  return null;
}

bool isVerificationMethodAuthorized(
  JsonMap didDocument,
  String relationship,
  String verificationMethodId,
) {
  final values = didDocument[relationship];
  if (values is! List) return false;
  return values.contains(verificationMethodId) ||
      values.any(
        (value) => value is Map && value['id'] == verificationMethodId,
      );
}

PublicKeyMaterial extractPublicKey(JsonMap method) {
  final jwk = method['publicKeyJwk'];
  if (jwk is Map) {
    return publicKeyFromJwk(
      Map<String, Object?>.from(jwk.cast<String, Object?>()),
    );
  }
  final multibase = method['publicKeyMultibase'];
  if (multibase is String && multibase.startsWith('z')) {
    return PublicKeyMaterial(
      type: KeyType.ed25519,
      bytes: decodeBase58(multibase.substring(1)),
    );
  }
  throw const FormatException(
    'verification method has no supported public key',
  );
}
