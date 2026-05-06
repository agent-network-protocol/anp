import '../codec/base58.dart';
import '../codec/base64.dart';
import '../codec/canonical_json.dart';
import 'key_material.dart';
import 'jwk.dart';

String computeJwkFingerprint(PublicKeyMaterial publicKey) =>
    encodeBase64Url(sha256Bytes(canonicalJsonBytes(publicKeyToJwk(publicKey))));

String computeMultikeyFingerprint(PublicKeyMaterial publicKey) {
  final prefix = switch (publicKey.type) {
    KeyType.ed25519 => [0xed, 0x01],
    KeyType.x25519 => [0xec, 0x01],
    KeyType.secp256k1 || KeyType.secp256r1 => <int>[],
  };
  return 'z${encodeBase58([...prefix, ...publicKey.bytes])}';
}

String ed25519PublicKeyToMultibase(List<int> bytes) =>
    'z${encodeBase58([0xed, 0x01, ...bytes])}';
String x25519PublicKeyToMultibase(List<int> bytes) =>
    'z${encodeBase58([0xec, 0x01, ...bytes])}';
