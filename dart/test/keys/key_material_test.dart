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
  test('PEM uses standard labels and rejects legacy ANP labels', () {
    final pair = generateKeyPairPem(KeyType.ed25519);
    expect(pair.pem.privateKeyPem, startsWith('-----BEGIN PRIVATE KEY-----'));
    expect(pair.pem.publicKeyPem, startsWith('-----BEGIN PUBLIC KEY-----'));
    expect(pair.pem.privateKeyPem.contains('ANP '), isFalse);
    expect(pair.pem.publicKeyPem.contains('ANP '), isFalse);

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
}
