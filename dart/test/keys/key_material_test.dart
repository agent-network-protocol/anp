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
}
