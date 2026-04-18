import 'dart:typed_data';

import '../errors.dart';

const String _alphabet =
    '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
final Map<String, int> _indexes = {
  for (var i = 0; i < _alphabet.length; i++) _alphabet[i]: i,
};

String encodeBase58(List<int> bytes) {
  if (bytes.isEmpty) return '';
  var value = BigInt.zero;
  for (final byte in bytes) {
    value = (value << 8) | BigInt.from(byte);
  }
  final buffer = StringBuffer();
  while (value > BigInt.zero) {
    final div = value ~/ BigInt.from(58);
    final mod = (value - div * BigInt.from(58)).toInt();
    buffer.write(_alphabet[mod]);
    value = div;
  }
  for (final byte in bytes) {
    if (byte == 0) {
      buffer.write(_alphabet[0]);
    } else {
      break;
    }
  }
  return buffer.toString().split('').reversed.join();
}

Uint8List decodeBase58(String input) {
  var value = BigInt.zero;
  for (final rune in input.runes) {
    final char = String.fromCharCode(rune);
    final index = _indexes[char];
    if (index == null) {
      throw AnpCodecException('invalid base58 character: $char');
    }
    value = value * BigInt.from(58) + BigInt.from(index);
  }
  final bytes = <int>[];
  while (value > BigInt.zero) {
    bytes.add((value & BigInt.from(0xff)).toInt());
    value >>= 8;
  }
  for (final rune in input.runes) {
    if (String.fromCharCode(rune) == _alphabet[0]) {
      bytes.add(0);
    } else {
      break;
    }
  }
  return Uint8List.fromList(bytes.reversed.toList());
}
