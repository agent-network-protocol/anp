import '../codec/base58.dart';
import 'key_material.dart';

String computeJwkFingerprint(PublicKeyMaterial publicKey) =>
    encodeBase58(sha256Bytes(publicKey.bytes));

String computeMultikeyFingerprint(PublicKeyMaterial publicKey) =>
    'z${encodeBase58(publicKey.bytes)}';

String ed25519PublicKeyToMultibase(List<int> bytes) =>
    'z${encodeBase58(bytes)}';
String x25519PublicKeyToMultibase(List<int> bytes) => 'z${encodeBase58(bytes)}';
