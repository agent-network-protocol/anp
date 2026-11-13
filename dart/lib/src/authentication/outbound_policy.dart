import '../errors.dart';
import 'http_auth_security.dart';

bool isPublicAddressBytes(List<int> bytes) {
  if (bytes.length == 4) {
    final a = bytes[0], b = bytes[1], c = bytes[2];
    return !(a == 0 ||
        a == 10 ||
        a == 127 ||
        a >= 224 ||
        a == 100 && b >= 64 && b <= 127 ||
        a == 169 && b == 254 ||
        a == 172 && b >= 16 && b <= 31 ||
        a == 192 && (b == 168 || b == 0 && (c == 0 || c == 2)) ||
        a == 198 && (b == 18 || b == 19 || b == 51 && c == 100) ||
        a == 203 && b == 0 && c == 113);
  }
  if (bytes.length != 16) return false;
  final words = [
    for (var i = 0; i < 16; i += 2) (bytes[i] << 8) | bytes[i + 1],
  ];
  if (words.take(5).every((v) => v == 0) && words[5] == 0xffff) {
    return isPublicAddressBytes(bytes.sublist(12));
  }
  return (words[0] & 0xe000) == 0x2000 &&
      !(words[0] == 0x2001 && (words[1] < 0x200 || words[1] == 0xdb8)) &&
      words[0] != 0x2002 &&
      (words[0] & 0xfff0) != 0x3ff0;
}

Uri validatePublicUri(String raw, {String? baseUrlOverride}) {
  authenticationOrigin(raw);
  final uri = Uri.parse(raw);
  if (baseUrlOverride != null) {
    final base = Uri.parse(baseUrlOverride);
    final prefix = base.path.replaceFirst(RegExp(r'/+$'), '');
    if (base.hasQuery ||
        baseUrlOverride.contains('#') ||
        authenticationOrigin(baseUrlOverride) != authenticationOrigin(raw) ||
        prefix.isNotEmpty &&
            uri.path != prefix &&
            !uri.path.startsWith('$prefix/')) {
      throw const AnpNetworkException('invalid trusted resolution override');
    }
    return uri;
  }
  if (uri.scheme != 'https') {
    throw const AnpNetworkException('public ANP requests require HTTPS');
  }
  final host = uri.host.toLowerCase().replaceFirst(RegExp(r'\.$'), '');
  if (host == 'localhost' || host.endsWith('.localhost')) {
    throw const AnpNetworkException('non-public ANP destination');
  }
  List<int>? address;
  try {
    address = host.contains(':')
        ? Uri.parseIPv6Address(host)
        : Uri.parseIPv4Address(host);
  } on FormatException {
    address = null;
  }
  if (address != null && !isPublicAddressBytes(address)) {
    throw const AnpNetworkException('non-public ANP destination');
  }
  return uri;
}
