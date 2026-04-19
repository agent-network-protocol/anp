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
    final decoded = decodeBase58(multibase.substring(1));
    if (decoded.length == 34 && decoded[0] == 0xed && decoded[1] == 0x01) {
      return PublicKeyMaterial(
        type: KeyType.ed25519,
        bytes: decoded.sublist(2),
      );
    }
    if (decoded.length == 34 && decoded[0] == 0xec && decoded[1] == 0x01) {
      return PublicKeyMaterial(type: KeyType.x25519, bytes: decoded.sublist(2));
    }
    return PublicKeyMaterial(type: KeyType.ed25519, bytes: decoded);
  }
  throw const FormatException(
    'verification method has no supported public key',
  );
}
