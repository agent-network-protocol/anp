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

  test('canonical json matches RFC 8785 number and string vectors', () {
    expect(
      canonicalJson({
        'numbers': [333333333.33333329, 1e30, 4.50, 2e-3, 1e-27, -0.0],
        'string': '€\$\u000f\nA\'B"\\\\"/',
        'literals': [null, true, false],
      }),
      '{"literals":[null,true,false],"numbers":'
      '[333333333.3333333,1e+30,4.5,0.002,1e-27,0],'
      '"string":"€\u0024\\u000f\\nA\'B\\"\\\\\\\\\\"/"}',
    );
  });

  test('canonical json sorts object names by UTF-16 code units', () {
    expect(
      canonicalJson({
        '€': 'euro',
        '\r': 'cr',
        'דּ': 'hebrew',
        '1': 'digit',
        '😀': 'emoji',
        '\u0080': 'control',
        'ö': 'oumlaut',
      }),
      '{"\\r":"cr","1":"digit","\u0080":"control","ö":"oumlaut",'
      '"€":"euro","😀":"emoji","דּ":"hebrew"}',
    );
  });
}
