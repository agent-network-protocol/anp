import '../codec/base64.dart';
import '../errors.dart';
import 'key_material.dart';

Map<String, Object?> publicKeyToJwk(PublicKeyMaterial publicKey) => {
  'kty': switch (publicKey.type) {
    KeyType.ed25519 || KeyType.x25519 => 'OKP',
    KeyType.secp256k1 || KeyType.secp256r1 => 'EC',
  },
  'crv': switch (publicKey.type) {
    KeyType.ed25519 => 'Ed25519',
    KeyType.x25519 => 'X25519',
    KeyType.secp256k1 => 'secp256k1',
    KeyType.secp256r1 => 'P-256',
  },
  'x': encodeBase64Url(publicKey.bytes),
};

PublicKeyMaterial publicKeyFromJwk(Map<String, Object?> jwk) {
  final crv = jwk['crv'];
  final x = jwk['x'];
  if (crv is! String || x is! String) {
    throw const AnpCryptoException('invalid public JWK');
  }
  final type = switch (crv) {
    'Ed25519' => KeyType.ed25519,
    'X25519' => KeyType.x25519,
    'secp256k1' => KeyType.secp256k1,
    'P-256' => KeyType.secp256r1,
    _ => throw AnpCryptoException('unsupported JWK curve: $crv'),
  };
  return PublicKeyMaterial(type: type, bytes: decodeBase64Url(x));
}
