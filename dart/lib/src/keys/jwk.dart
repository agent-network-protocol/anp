import 'dart:typed_data';

import 'package:pointycastle/ecc/api.dart' as ec;
import 'package:pointycastle/ecc/curves/secp256k1.dart';
import 'package:pointycastle/ecc/curves/secp256r1.dart';

import '../codec/base64.dart';
import '../errors.dart';
import 'key_material.dart';

Map<String, Object?> publicKeyToJwk(PublicKeyMaterial publicKey) {
  switch (publicKey.type) {
    case KeyType.ed25519:
      return {
        'kty': 'OKP',
        'crv': 'Ed25519',
        'x': encodeBase64Url(publicKey.bytes),
      };
    case KeyType.x25519:
      return {
        'kty': 'OKP',
        'crv': 'X25519',
        'x': encodeBase64Url(publicKey.bytes),
      };
    case KeyType.secp256k1:
    case KeyType.secp256r1:
      final point = _domain(publicKey.type).curve.decodePoint(publicKey.bytes);
      if (point == null) {
        throw const AnpCryptoException('invalid EC public key');
      }
      final uncompressed = point.getEncoded(false);
      return {
        'kty': 'EC',
        'crv': publicKey.type == KeyType.secp256k1 ? 'secp256k1' : 'P-256',
        'x': encodeBase64Url(uncompressed.sublist(1, 33)),
        'y': encodeBase64Url(uncompressed.sublist(33, 65)),
      };
  }
}

PublicKeyMaterial publicKeyFromJwk(Map<String, Object?> jwk) {
  final kty = jwk['kty'];
  final crv = jwk['crv'];
  final x = jwk['x'];
  if (kty is! String || crv is! String || x is! String) {
    throw const AnpCryptoException('invalid public JWK');
  }
  if (kty == 'OKP') {
    final type = switch (crv) {
      'Ed25519' => KeyType.ed25519,
      'X25519' => KeyType.x25519,
      _ => throw AnpCryptoException('unsupported JWK curve: $crv'),
    };
    return PublicKeyMaterial(type: type, bytes: decodeBase64Url(x));
  }
  if (kty == 'EC') {
    final y = jwk['y'];
    if (y is! String) {
      throw const AnpCryptoException('EC public JWK requires y');
    }
    final type = switch (crv) {
      'secp256k1' => KeyType.secp256k1,
      'P-256' => KeyType.secp256r1,
      _ => throw AnpCryptoException('unsupported JWK curve: $crv'),
    };
    final point = _domain(type).curve.decodePoint(
      Uint8List.fromList([0x04, ...decodeBase64Url(x), ...decodeBase64Url(y)]),
    );
    if (point == null) {
      throw const AnpCryptoException('invalid EC public JWK point');
    }
    return PublicKeyMaterial(
      type: type,
      bytes: Uint8List.fromList(point.getEncoded(true)),
    );
  }
  throw AnpCryptoException('unsupported JWK key type: $kty');
}

ec.ECDomainParameters _domain(KeyType type) => switch (type) {
  KeyType.secp256k1 => ECCurve_secp256k1(),
  KeyType.secp256r1 => ECCurve_secp256r1(),
  _ => throw AnpCryptoException('not an EC key type: ${type.wireName}'),
};
