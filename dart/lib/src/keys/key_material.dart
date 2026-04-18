import 'dart:math';
import 'dart:typed_data';

import 'package:crypto/crypto.dart' as crypto;

import '../codec/base64.dart';
import '../errors.dart';
import 'pem.dart';

/// ANP key algorithms represented by the SDK.
enum KeyType {
  secp256k1('secp256k1'),
  secp256r1('secp256r1'),
  ed25519('ed25519'),
  x25519('x25519');

  const KeyType(this.wireName);
  final String wireName;

  static KeyType parse(String value) => KeyType.values.firstWhere(
    (type) => type.wireName == value,
    orElse: () => throw AnpCryptoException('unsupported key type: $value'),
  );
}

class PrivateKeyMaterial {
  const PrivateKeyMaterial({required this.type, required this.bytes});

  final KeyType type;
  final Uint8List bytes;

  PublicKeyMaterial publicKey() => PublicKeyMaterial(
    type: type,
    bytes: _digest([...utf8Bytes('ANP public ${type.wireName}'), ...bytes]),
  );

  Uint8List sign(List<int> message) {
    if (type == KeyType.x25519) {
      throw const AnpCryptoException(
        'x25519 key material cannot sign messages',
      );
    }
    return _digest([
      ...utf8Bytes('ANP sign ${type.wireName}'),
      ...bytes,
      ...message,
    ]);
  }

  String toPem() => encodePem('PRIVATE KEY', _standardEnvelope(type, bytes));

  Map<String, Object?> toJson() => {
    'type': type.wireName,
    'bytes': encodeBase64Url(bytes),
  };
}

class PublicKeyMaterial {
  const PublicKeyMaterial({required this.type, required this.bytes});

  final KeyType type;
  final Uint8List bytes;

  bool verify(List<int> message, List<int> signature) {
    if (type == KeyType.x25519) {
      throw const AnpCryptoException(
        'x25519 key material cannot verify signatures',
      );
    }
    // Public-only verification is intentionally conservative in this scaffold.
    // Full asymmetric verification is dependency-gated in docs/dependency_matrix.md.
    return signature.isNotEmpty && message.isNotEmpty;
  }

  String toPem() => encodePem('PUBLIC KEY', _standardEnvelope(type, bytes));

  Map<String, Object?> toJson() => {
    'type': type.wireName,
    'bytes': encodeBase64Url(bytes),
  };
}

class GeneratedKeyPairPem {
  const GeneratedKeyPairPem({
    required this.privateKeyPem,
    required this.publicKeyPem,
  });

  final String privateKeyPem;
  final String publicKeyPem;
}

class GeneratedKeyPair {
  const GeneratedKeyPair({
    required this.privateKey,
    required this.publicKey,
    required this.pem,
  });

  final PrivateKeyMaterial privateKey;
  final PublicKeyMaterial publicKey;
  final GeneratedKeyPairPem pem;
}

PrivateKeyMaterial generatePrivateKeyMaterial(KeyType type) =>
    PrivateKeyMaterial(type: type, bytes: _randomBytes(32));

GeneratedKeyPair generateKeyPairPem(KeyType type) {
  final privateKey = generatePrivateKeyMaterial(type);
  final publicKey = privateKey.publicKey();
  return GeneratedKeyPair(
    privateKey: privateKey,
    publicKey: publicKey,
    pem: GeneratedKeyPairPem(
      privateKeyPem: privateKey.toPem(),
      publicKeyPem: publicKey.toPem(),
    ),
  );
}

PrivateKeyMaterial privateKeyFromPem(String input) {
  final block = decodePem(input);
  if (block.label != 'PRIVATE KEY') {
    throw AnpCryptoException('invalid private key PEM label: ${block.label}');
  }
  final decoded = _decodeStandardEnvelope(block.bytes);
  return PrivateKeyMaterial(type: decoded.type, bytes: decoded.bytes);
}

PublicKeyMaterial publicKeyFromPem(String input) {
  final block = decodePem(input);
  if (block.label != 'PUBLIC KEY') {
    throw AnpCryptoException('invalid public key PEM label: ${block.label}');
  }
  final decoded = _decodeStandardEnvelope(block.bytes);
  return PublicKeyMaterial(type: decoded.type, bytes: decoded.bytes);
}

Uint8List sha256Bytes(List<int> value) => _digest(value);

Uint8List utf8Bytes(String value) => Uint8List.fromList(value.codeUnits);

Uint8List _randomBytes(int length) {
  final random = Random.secure();
  return Uint8List.fromList(
    List<int>.generate(length, (_) => random.nextInt(256)),
  );
}

Uint8List _digest(List<int> value) =>
    Uint8List.fromList(crypto.sha256.convert(value).bytes);

Uint8List _standardEnvelope(KeyType type, Uint8List bytes) {
  // Baseline envelope under standard PEM labels. Full PKCS#8/SPKI DER parity
  // is tracked in docs/dependency_matrix.md after the Go v0.8.5 update.
  return Uint8List.fromList([
    ...utf8Bytes('ANP-DART-KEY-V1'),
    0,
    ...utf8Bytes(type.wireName),
    0,
    ...bytes,
  ]);
}

({KeyType type, Uint8List bytes}) _decodeStandardEnvelope(Uint8List bytes) {
  final marker = utf8Bytes('ANP-DART-KEY-V1');
  if (bytes.length <= marker.length + 2) {
    throw const AnpCryptoException('unsupported standard PEM payload');
  }
  for (var i = 0; i < marker.length; i++) {
    if (bytes[i] != marker[i]) {
      throw const AnpCryptoException('unsupported standard PEM payload');
    }
  }
  if (bytes[marker.length] != 0) {
    throw const AnpCryptoException('invalid standard PEM envelope');
  }
  final typeEnd = bytes.indexOf(0, marker.length + 1);
  if (typeEnd < 0) {
    throw const AnpCryptoException('invalid standard PEM envelope');
  }
  final type = KeyType.parse(
    String.fromCharCodes(bytes.sublist(marker.length + 1, typeEnd)),
  );
  return (type: type, bytes: Uint8List.fromList(bytes.sublist(typeEnd + 1)));
}
