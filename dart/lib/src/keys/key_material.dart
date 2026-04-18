import 'dart:math';
import 'dart:typed_data';

import 'package:crypto/crypto.dart' as crypto;
import 'package:pinenacl/ed25519.dart' as ed25519;
import 'package:pinenacl/x25519.dart' as x25519;
import 'package:pointycastle/api.dart' as pc;
import 'package:pointycastle/ecc/api.dart' as ec;
import 'package:pointycastle/ecc/curves/secp256k1.dart';
import 'package:pointycastle/ecc/curves/secp256r1.dart';
import 'package:pointycastle/random/fortuna_random.dart';
import 'package:pointycastle/signers/ecdsa_signer.dart';

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

  PublicKeyMaterial publicKey() {
    switch (type) {
      case KeyType.secp256k1:
      case KeyType.secp256r1:
        final domain = _domain(type);
        final point = domain.G * _bigIntFromBytes(bytes);
        if (point == null || point.isInfinity) {
          throw const AnpCryptoException('invalid EC private key');
        }
        return PublicKeyMaterial(
          type: type,
          bytes: Uint8List.fromList(point.getEncoded(true)),
        );
      case KeyType.ed25519:
        return PublicKeyMaterial(
          type: type,
          bytes: Uint8List.fromList(
            ed25519.SigningKey(seed: bytes).verifyKey.asTypedList,
          ),
        );
      case KeyType.x25519:
        return PublicKeyMaterial(
          type: type,
          bytes: Uint8List.fromList(
            x25519.PrivateKey(bytes).publicKey.asTypedList,
          ),
        );
    }
  }

  Uint8List sign(List<int> message) {
    switch (type) {
      case KeyType.secp256k1:
      case KeyType.secp256r1:
        final domain = _domain(type);
        final signer = ECDSASigner()
          ..init(
            true,
            pc.ParametersWithRandom(
              pc.PrivateKeyParameter<ec.ECPrivateKey>(
                ec.ECPrivateKey(_bigIntFromBytes(bytes), domain),
              ),
              _secureRandom(),
            ),
          );
        final signature =
            signer.generateSignature(sha256Bytes(message)) as ec.ECSignature;
        return Uint8List.fromList([
          ..._bigIntToFixed(signature.r, 32),
          ..._bigIntToFixed(signature.s, 32),
        ]);
      case KeyType.ed25519:
        return Uint8List.fromList(
          ed25519.SigningKey(
            seed: bytes,
          ).sign(Uint8List.fromList(message)).signature.asTypedList,
        );
      case KeyType.x25519:
        throw const AnpCryptoException(
          'x25519 key material cannot sign messages',
        );
    }
  }

  String toPem() =>
      encodePem('PRIVATE KEY', _pkcs8Der(type, bytes, publicKey().bytes));

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
    switch (type) {
      case KeyType.secp256k1:
      case KeyType.secp256r1:
        if (signature.length != 64) return false;
        final domain = _domain(type);
        final point = domain.curve.decodePoint(bytes);
        if (point == null) return false;
        final verifier = ECDSASigner()
          ..init(
            false,
            pc.PublicKeyParameter<ec.ECPublicKey>(
              ec.ECPublicKey(point, domain),
            ),
          );
        return verifier.verifySignature(
          sha256Bytes(message),
          ec.ECSignature(
            _bigIntFromBytes(signature.sublist(0, 32)),
            _bigIntFromBytes(signature.sublist(32, 64)),
          ),
        );
      case KeyType.ed25519:
        try {
          return ed25519.VerifyKey(bytes).verify(
            signature: ed25519.Signature(Uint8List.fromList(signature)),
            message: Uint8List.fromList(message),
          );
        } catch (_) {
          return false;
        }
      case KeyType.x25519:
        throw const AnpCryptoException(
          'x25519 key material cannot verify signatures',
        );
    }
  }

  String toPem() => encodePem('PUBLIC KEY', _spkiDer(type, bytes));

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

PrivateKeyMaterial generatePrivateKeyMaterial(KeyType type) {
  switch (type) {
    case KeyType.secp256k1:
    case KeyType.secp256r1:
      final domain = _domain(type);
      while (true) {
        final bytes = _randomBytes(32);
        final scalar = _bigIntFromBytes(bytes);
        if (scalar > BigInt.zero && scalar < domain.n) {
          return PrivateKeyMaterial(type: type, bytes: bytes);
        }
      }
    case KeyType.ed25519:
    case KeyType.x25519:
      return PrivateKeyMaterial(type: type, bytes: _randomBytes(32));
  }
}

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
  final decoded = _parsePkcs8(block.bytes);
  return PrivateKeyMaterial(type: decoded.type, bytes: decoded.bytes);
}

PublicKeyMaterial publicKeyFromPem(String input) {
  final block = decodePem(input);
  if (block.label != 'PUBLIC KEY') {
    throw AnpCryptoException('invalid public key PEM label: ${block.label}');
  }
  final decoded = _parseSpki(block.bytes);
  return PublicKeyMaterial(type: decoded.type, bytes: decoded.bytes);
}

Uint8List sha256Bytes(List<int> value) =>
    Uint8List.fromList(crypto.sha256.convert(value).bytes);

Uint8List utf8Bytes(String value) => Uint8List.fromList(value.codeUnits);

Uint8List _randomBytes(int length) {
  final random = Random.secure();
  return Uint8List.fromList(
    List<int>.generate(length, (_) => random.nextInt(256)),
  );
}

pc.SecureRandom _secureRandom() =>
    FortunaRandom()..seed(pc.KeyParameter(_randomBytes(32)));

ec.ECDomainParameters _domain(KeyType type) => switch (type) {
  KeyType.secp256k1 => ECCurve_secp256k1(),
  KeyType.secp256r1 => ECCurve_secp256r1(),
  _ => throw AnpCryptoException('not an EC key type: ${type.wireName}'),
};

Uint8List _pkcs8Der(
  KeyType type,
  Uint8List privateBytes,
  Uint8List publicBytes,
) {
  switch (type) {
    case KeyType.ed25519:
      return _sequence([
        _integer(0),
        _algorithm([1, 3, 101, 112]),
        _octetString(_octetString(privateBytes)),
      ]);
    case KeyType.x25519:
      return _sequence([
        _integer(0),
        _algorithm([1, 3, 101, 110]),
        _octetString(_octetString(privateBytes)),
      ]);
    case KeyType.secp256r1:
      return _sequence([
        _integer(0),
        _algorithm(_oidEcPublicKey, paramsOid: _oidPrime256v1),
        _octetString(
          _ecPrivateKey(privateBytes, _ecUncompressed(type, publicBytes)),
        ),
      ]);
    case KeyType.secp256k1:
      return _sequence([
        _integer(0),
        _algorithm(_oidEcPublicKey, paramsOid: _oidSecp256k1),
        _octetString(
          _ecPrivateKey(
            privateBytes,
            _ecUncompressed(type, publicBytes),
            namedCurve: _oidSecp256k1,
          ),
        ),
      ]);
  }
}

Uint8List _spkiDer(KeyType type, Uint8List publicBytes) {
  switch (type) {
    case KeyType.ed25519:
      return _sequence([
        _algorithm([1, 3, 101, 112]),
        _bitString(publicBytes),
      ]);
    case KeyType.x25519:
      return _sequence([
        _algorithm([1, 3, 101, 110]),
        _bitString(publicBytes),
      ]);
    case KeyType.secp256r1:
      return _sequence([
        _algorithm(_oidEcPublicKey, paramsOid: _oidPrime256v1),
        _bitString(_ecUncompressed(type, publicBytes)),
      ]);
    case KeyType.secp256k1:
      return _sequence([
        _algorithm(_oidEcPublicKey, paramsOid: _oidSecp256k1),
        _bitString(_ecUncompressed(type, publicBytes)),
      ]);
  }
}

Uint8List _ecPrivateKey(
  Uint8List privateBytes,
  Uint8List publicUncompressed, {
  List<int>? namedCurve,
}) {
  return _sequence([
    _integer(1),
    _octetString(privateBytes),
    if (namedCurve != null) _explicit(0, _oid(namedCurve)),
    _explicit(1, _bitString(publicUncompressed)),
  ]);
}

Uint8List _ecUncompressed(KeyType type, Uint8List publicBytes) {
  final domain = _domain(type);
  final point = domain.curve.decodePoint(publicBytes);
  if (point == null) {
    throw const AnpCryptoException('invalid EC public key bytes');
  }
  return Uint8List.fromList(point.getEncoded(false));
}

({KeyType type, Uint8List bytes}) _parsePkcs8(Uint8List der) {
  final reader = _DerReader(der).readSequence();
  reader.readInteger();
  final alg = reader.readAlgorithm();
  final privateOctets = reader.readOctetString();
  reader.expectDone();

  if (_oidEquals(alg.algorithm, [1, 3, 101, 112])) {
    return (
      type: KeyType.ed25519,
      bytes: _DerReader(privateOctets).readOnlyOctetString(),
    );
  }
  if (_oidEquals(alg.algorithm, [1, 3, 101, 110])) {
    return (
      type: KeyType.x25519,
      bytes: _DerReader(privateOctets).readOnlyOctetString(),
    );
  }
  if (!_oidEquals(alg.algorithm, _oidEcPublicKey)) {
    throw const AnpCryptoException('unsupported PKCS#8 algorithm');
  }
  final type = _curveOidToKeyType(alg.parametersOid);
  final ecReader = _DerReader(privateOctets).readSequence();
  ecReader.readInteger();
  final scalar = ecReader.readOctetString();
  return (
    type: type,
    bytes: scalar.length == 32
        ? scalar
        : Uint8List.fromList(_leftPad(scalar, 32)),
  );
}

({KeyType type, Uint8List bytes}) _parseSpki(Uint8List der) {
  final reader = _DerReader(der).readSequence();
  final alg = reader.readAlgorithm();
  final publicBits = reader.readBitString();
  reader.expectDone();
  if (_oidEquals(alg.algorithm, [1, 3, 101, 112])) {
    return (type: KeyType.ed25519, bytes: publicBits);
  }
  if (_oidEquals(alg.algorithm, [1, 3, 101, 110])) {
    return (type: KeyType.x25519, bytes: publicBits);
  }
  if (!_oidEquals(alg.algorithm, _oidEcPublicKey)) {
    throw const AnpCryptoException('unsupported SPKI algorithm');
  }
  final type = _curveOidToKeyType(alg.parametersOid);
  final point = _domain(type).curve.decodePoint(publicBits);
  if (point == null) {
    throw const AnpCryptoException('invalid EC SPKI public key');
  }
  return (type: type, bytes: Uint8List.fromList(point.getEncoded(true)));
}

KeyType _curveOidToKeyType(List<int>? oid) {
  if (_oidEquals(oid, _oidPrime256v1)) return KeyType.secp256r1;
  if (_oidEquals(oid, _oidSecp256k1)) return KeyType.secp256k1;
  throw const AnpCryptoException('unsupported EC curve OID');
}

const List<int> _oidEcPublicKey = [1, 2, 840, 10045, 2, 1];
const List<int> _oidPrime256v1 = [1, 2, 840, 10045, 3, 1, 7];
const List<int> _oidSecp256k1 = [1, 3, 132, 0, 10];

Uint8List _algorithm(List<int> algorithmOid, {List<int>? paramsOid}) =>
    _sequence([_oid(algorithmOid), if (paramsOid != null) _oid(paramsOid)]);

Uint8List _sequence(List<List<int>> parts) => _tlv(0x30, _concat(parts));
Uint8List _integer(int value) => _tlv(0x02, Uint8List.fromList([value]));
Uint8List _octetString(List<int> value) =>
    _tlv(0x04, Uint8List.fromList(value));
Uint8List _bitString(List<int> value) =>
    _tlv(0x03, Uint8List.fromList([0, ...value]));
Uint8List _explicit(int tag, List<int> value) =>
    _tlv(0xa0 + tag, Uint8List.fromList(value));

Uint8List _oid(List<int> oid) {
  final out = <int>[oid[0] * 40 + oid[1]];
  for (final part in oid.skip(2)) {
    final stack = <int>[part & 0x7f];
    var value = part >> 7;
    while (value > 0) {
      stack.add(0x80 | (value & 0x7f));
      value >>= 7;
    }
    out.addAll(stack.reversed);
  }
  return _tlv(0x06, Uint8List.fromList(out));
}

Uint8List _tlv(int tag, Uint8List value) =>
    Uint8List.fromList([tag, ..._length(value.length), ...value]);

List<int> _length(int length) {
  if (length < 0x80) return [length];
  final bytes = <int>[];
  var value = length;
  while (value > 0) {
    bytes.add(value & 0xff);
    value >>= 8;
  }
  return [0x80 | bytes.length, ...bytes.reversed];
}

Uint8List _concat(List<List<int>> parts) =>
    Uint8List.fromList([for (final part in parts) ...part]);

BigInt _bigIntFromBytes(List<int> bytes) {
  var result = BigInt.zero;
  for (final byte in bytes) {
    result = (result << 8) | BigInt.from(byte);
  }
  return result;
}

Uint8List _bigIntToFixed(BigInt value, int length) {
  final out = Uint8List(length);
  var current = value;
  for (var i = length - 1; i >= 0; i--) {
    out[i] = (current & BigInt.from(0xff)).toInt();
    current >>= 8;
  }
  return out;
}

List<int> _leftPad(List<int> bytes, int length) => [
  for (var i = bytes.length; i < length; i++) 0,
  ...bytes,
];

bool _oidEquals(List<int>? left, List<int> right) {
  if (left == null || left.length != right.length) return false;
  for (var i = 0; i < left.length; i++) {
    if (left[i] != right[i]) return false;
  }
  return true;
}

class _AlgorithmIdentifier {
  const _AlgorithmIdentifier(this.algorithm, this.parametersOid);
  final List<int> algorithm;
  final List<int>? parametersOid;
}

class _DerReader {
  _DerReader(Uint8List bytes) : _bytes = bytes;

  final Uint8List _bytes;
  int _offset = 0;

  _DerReader readSequence() => _DerReader(_read(0x30));

  int readInteger() {
    final bytes = _read(0x02);
    return _bigIntFromBytes(bytes).toInt();
  }

  Uint8List readOctetString() => _read(0x04);

  Uint8List readBitString() {
    final bytes = _read(0x03);
    if (bytes.isEmpty || bytes.first != 0) {
      throw const AnpCryptoException('unsupported DER bit string');
    }
    return Uint8List.fromList(bytes.sublist(1));
  }

  _AlgorithmIdentifier readAlgorithm() {
    final sequence = readSequence();
    final algorithm = sequence.readOid();
    List<int>? params;
    if (!sequence.isDone) {
      params = sequence.readOid();
    }
    sequence.expectDone();
    return _AlgorithmIdentifier(algorithm, params);
  }

  Uint8List readOnlyOctetString() {
    final value = readOctetString();
    expectDone();
    return value;
  }

  List<int> readOid() {
    final bytes = _read(0x06);
    if (bytes.isEmpty) throw const AnpCryptoException('invalid DER OID');
    final values = <int>[bytes.first ~/ 40, bytes.first % 40];
    var value = 0;
    for (final byte in bytes.skip(1)) {
      value = (value << 7) | (byte & 0x7f);
      if ((byte & 0x80) == 0) {
        values.add(value);
        value = 0;
      }
    }
    return values;
  }

  bool get isDone => _offset == _bytes.length;

  void expectDone() {
    if (!isDone) throw const AnpCryptoException('trailing DER data');
  }

  Uint8List _read(int tag) {
    if (_offset >= _bytes.length || _bytes[_offset++] != tag) {
      throw const AnpCryptoException('unexpected DER tag');
    }
    final len = _readLength();
    if (_offset + len > _bytes.length) {
      throw const AnpCryptoException('truncated DER value');
    }
    final value = Uint8List.fromList(_bytes.sublist(_offset, _offset + len));
    _offset += len;
    return value;
  }

  int _readLength() {
    if (_offset >= _bytes.length) {
      throw const AnpCryptoException('truncated DER length');
    }
    final first = _bytes[_offset++];
    if ((first & 0x80) == 0) return first;
    final count = first & 0x7f;
    if (count == 0 || count > 4 || _offset + count > _bytes.length) {
      throw const AnpCryptoException('invalid DER length');
    }
    var length = 0;
    for (var i = 0; i < count; i++) {
      length = (length << 8) | _bytes[_offset++];
    }
    return length;
  }
}
