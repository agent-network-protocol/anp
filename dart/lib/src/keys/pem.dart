import 'dart:convert';
import 'dart:typed_data';

import '../errors.dart';

class PemBlock {
  const PemBlock({required this.label, required this.bytes});

  final String label;
  final Uint8List bytes;
}

String encodePem(String label, List<int> bytes) {
  final body = base64Encode(
    bytes,
  ).replaceAllMapped(RegExp('.{1,64}'), (match) => '${match.group(0)}\n');
  return '-----BEGIN $label-----\n$body-----END $label-----\n';
}

PemBlock decodePem(String input) {
  final match = RegExp(
    r'-----BEGIN ([^-]+)-----\s*([A-Za-z0-9+/=\s]+)-----END \1-----',
    multiLine: true,
  ).firstMatch(input.trim());
  if (match == null) throw const AnpCryptoException('invalid PEM block');
  return PemBlock(
    label: match.group(1)!,
    bytes: Uint8List.fromList(
      base64Decode(match.group(2)!.replaceAll(RegExp(r'\s+'), '')),
    ),
  );
}
