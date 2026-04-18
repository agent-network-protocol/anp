import 'dart:convert';
import 'dart:typed_data';

import '../errors.dart';

Uint8List canonicalJsonBytes(Object? value) =>
    Uint8List.fromList(utf8.encode(canonicalJson(value)));

String canonicalJson(Object? value) => jsonEncode(_normalize(value));

Object? _normalize(Object? value) {
  if (value == null || value is bool || value is String || value is int) {
    return value;
  }
  if (value is double) {
    if (!value.isFinite) {
      throw const AnpCodecException('non-finite JSON number');
    }
    if (value == value.truncateToDouble()) return value.toInt();
    return value;
  }
  if (value is Iterable<Object?>) {
    return value.map(_normalize).toList(growable: false);
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
    return {for (final key in keys) key: _normalize(value[key])};
  }
  throw AnpCodecException(
    'unsupported canonical JSON value: ${value.runtimeType}',
  );
}

Map<String, Object?> cloneJsonMap(Map<String, Object?> input) =>
    jsonDecode(jsonEncode(input)) as Map<String, Object?>;
