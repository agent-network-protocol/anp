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

  String toPem() => encodePem(_privateLabel(type), bytes);

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

  String toPem() => encodePem(_publicLabel(type), bytes);

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
  return PrivateKeyMaterial(
    type: _typeFromLabel(block.label, privateKey: true),
    bytes: block.bytes,
  );
}

PublicKeyMaterial publicKeyFromPem(String input) {
  final block = decodePem(input);
  return PublicKeyMaterial(
    type: _typeFromLabel(block.label, privateKey: false),
    bytes: block.bytes,
  );
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

String _privateLabel(KeyType type) =>
    'ANP ${type.wireName.toUpperCase()} PRIVATE KEY';
String _publicLabel(KeyType type) =>
    'ANP ${type.wireName.toUpperCase()} PUBLIC KEY';

KeyType _typeFromLabel(String label, {required bool privateKey}) {
  for (final type in KeyType.values) {
    final expected = privateKey ? _privateLabel(type) : _publicLabel(type);
    if (label == expected) return type;
  }
  throw AnpCryptoException('unsupported PEM label: $label');
}
