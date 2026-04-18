import 'package:anp/anp.dart';
import 'package:test/test.dart';

void main() {
  test('generates key material and PEM round trips', () {
    final key = generatePrivateKeyMaterial(KeyType.ed25519);
    final pem = key.toPem();
    final parsed = privateKeyFromPem(pem);
    expect(parsed.type, key.type);
    expect(parsed.bytes, key.bytes);
  });

  test('x25519 cannot sign', () {
    final key = generatePrivateKeyMaterial(KeyType.x25519);
    expect(() => key.sign([1, 2, 3]), throwsA(isA<AnpCryptoException>()));
  });
  test('PEM uses standard PKCS8/SPKI labels and rejects legacy ANP labels', () {
    for (final type in KeyType.values) {
      final pair = generateKeyPairPem(type);
      expect(pair.pem.privateKeyPem, startsWith('-----BEGIN PRIVATE KEY-----'));
      expect(pair.pem.publicKeyPem, startsWith('-----BEGIN PUBLIC KEY-----'));
      expect(pair.pem.privateKeyPem.contains('ANP '), isFalse);
      expect(pair.pem.publicKeyPem.contains('ANP '), isFalse);
      expect(privateKeyFromPem(pair.pem.privateKeyPem).type, type);
      expect(publicKeyFromPem(pair.pem.publicKeyPem).type, type);
    }

    expect(
      () => privateKeyFromPem(
        '-----BEGIN ANP ED25519 PRIVATE KEY-----\nAAAA\n-----END ANP ED25519 PRIVATE KEY-----',
      ),
      throwsA(isA<AnpCryptoException>()),
    );
    expect(
      () => publicKeyFromPem(
        '-----BEGIN ANP ED25519 PUBLIC KEY-----\nAAAA\n-----END ANP ED25519 PUBLIC KEY-----',
      ),
      throwsA(isA<AnpCryptoException>()),
    );
  });
  test('EC public JWK includes x and y coordinates', () {
    for (final type in [KeyType.secp256k1, KeyType.secp256r1]) {
      final publicKey = generatePrivateKeyMaterial(type).publicKey();
      final jwk = publicKeyToJwk(publicKey);
      expect(jwk['kty'], 'EC');
      expect(jwk['x'], isA<String>());
      expect(jwk['y'], isA<String>());
      expect(publicKeyFromJwk(jwk).bytes, publicKey.bytes);
    }
  });
}
