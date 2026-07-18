import 'dart:convert';
import 'dart:typed_data';

import '../errors.dart';

Uint8List canonicalJsonBytes(Object? value) =>
    Uint8List.fromList(utf8.encode(canonicalJson(value)));

/// Serializes [value] using the RFC 8785 JSON Canonicalization Scheme.
///
/// Dart's ordinary `jsonEncode` preserves a `.0` suffix and the previous
/// implementation converted integral doubles to `int`. The latter overflows
/// for values such as `1e30`. Writing numbers directly keeps the IEEE-754
/// shortest representation while applying the ECMAScript/JCS `-0` and `.0`
/// normalization rules.
String canonicalJson(Object? value) {
  final output = StringBuffer();
  _writeCanonical(output, value);
  return output.toString();
}

void _writeCanonical(StringBuffer output, Object? value) {
  if (value == null) {
    output.write('null');
    return;
  }
  if (value is bool) {
    output.write(value ? 'true' : 'false');
    return;
  }
  if (value is String) {
    output.write(jsonEncode(value));
    return;
  }
  if (value is int) {
    output.write(value);
    return;
  }
  if (value is double) {
    output.write(_canonicalDouble(value));
    return;
  }
  if (value is Iterable<Object?>) {
    output.write('[');
    var first = true;
    for (final item in value) {
      if (!first) output.write(',');
      first = false;
      _writeCanonical(output, item);
    }
    output.write(']');
    return;
  }
  if (value is Map<Object?, Object?>) {
    final keys = value.keys.map((key) {
      if (key is! String) {
        throw const AnpCodecException(
          'canonical JSON object keys must be strings',
        );
      }
      return key;
    }).toList()..sort();
    output.write('{');
    for (var index = 0; index < keys.length; index++) {
      if (index != 0) output.write(',');
      output.write(jsonEncode(keys[index]));
      output.write(':');
      _writeCanonical(output, value[keys[index]]);
    }
    output.write('}');
    return;
  }
  throw AnpCodecException(
    'unsupported canonical JSON value: ${value.runtimeType}',
  );
}

String _canonicalDouble(double value) {
  if (!value.isFinite) {
    throw const AnpCodecException('non-finite JSON number');
  }
  if (value == 0) return '0';
  final encoded = value.toString();
  return encoded.endsWith('.0')
      ? encoded.substring(0, encoded.length - 2)
      : encoded;
}

Map<String, Object?> cloneJsonMap(Map<String, Object?> input) =>
    jsonDecode(jsonEncode(input)) as Map<String, Object?>;
