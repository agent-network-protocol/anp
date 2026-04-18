import 'package:anp/anp.dart';
import 'package:test/test.dart';

void main() {
  test('base64url round trip', () {
    final encoded = encodeBase64Url([1, 2, 3, 254]);
    expect(decodeBase64Url(encoded), [1, 2, 3, 254]);
  });

  test('base58 round trip', () {
    final encoded = encodeBase58([0, 1, 2, 3, 255]);
    expect(decodeBase58(encoded), [0, 1, 2, 3, 255]);
  });

  test('canonical json sorts keys', () {
    expect(canonicalJson({'b': 1, 'a': 2}), '{"a":2,"b":1}');
  });
}
