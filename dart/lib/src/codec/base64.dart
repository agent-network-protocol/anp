import 'dart:convert';
import 'dart:typed_data';

import '../errors.dart';

String encodeBase64Url(List<int> value) =>
    base64UrlEncode(value).replaceAll('=', '');

Uint8List decodeBase64Url(String value) {
  try {
    final normalized = value.padRight(
      value.length + ((4 - value.length % 4) % 4),
      '=',
    );
    return Uint8List.fromList(base64Url.decode(normalized));
  } on FormatException catch (error) {
    throw AnpCodecException('invalid base64url value', cause: error);
  }
}

String encodeBase64(List<int> value) => base64Encode(value);

Uint8List decodeBase64(String value) {
  try {
    return Uint8List.fromList(base64.decode(value));
  } on FormatException catch (error) {
    throw AnpCodecException('invalid base64 value', cause: error);
  }
}
