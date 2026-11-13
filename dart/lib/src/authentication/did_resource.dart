import '../errors.dart';
import 'http_auth_security.dart';
import 'did_wba.dart';
import 'types.dart';

/// Syntax only, with no DNS or transport side effects. Overrides are host-only.
String buildDidResolutionUrl(String did, {String? baseUrlOverride}) {
  final parts = did.split(':');
  if (parts.length < 3 ||
      parts.first != 'did' ||
      !const ['wba', 'web'].contains(parts[1])) {
    throw const AnpAuthenticationException('unsupported DID method');
  }
  final authority = Uri.decodeComponent(parts[2]);
  if (authority.isEmpty ||
      RegExp(r'[/\\?#%@\x00-\x20\x7f]').hasMatch(authority)) {
    throw const AnpAuthenticationException('invalid DID authority');
  }
  authenticationOrigin('https://$authority');
  final host = Uri.parse('https://$authority').host;
  if (parts[1] == 'web') {
    final labels = host.split('.');
    if (host.length > 253 ||
        labels.length < 2 ||
        !RegExp('[A-Za-z]').hasMatch(labels.last) ||
        labels.any(
          (label) => !RegExp(
            r'^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$',
          ).hasMatch(label),
        )) {
      throw const AnpAuthenticationException('DID Web requires a DNS hostname');
    }
  }
  final segments = parts.skip(3).map((raw) {
    final value = Uri.decodeComponent(raw);
    if (value.isEmpty ||
        value == '.' ||
        value == '..' ||
        RegExp(r'[/\\?#%\x00-\x1f\x7f]').hasMatch(value)) {
      throw const AnpAuthenticationException('unsafe DID path component');
    }
    return Uri.encodeComponent(value);
  }).toList();
  var base = 'https://$authority';
  if (baseUrlOverride != null) {
    authenticationOrigin(baseUrlOverride);
    if (Uri.parse(baseUrlOverride).hasQuery || baseUrlOverride.contains('#')) {
      throw const AnpAuthenticationException(
        'invalid trusted resolution override',
      );
    }
    base = baseUrlOverride.replaceFirst(RegExp(r'/+$'), '');
  }
  return '$base/${segments.isEmpty ? '.well-known/did.json' : '${segments.join('/')}/did.json'}';
}

/// Validates method structure/binding after trusted resolution, not permissions.
bool validateDidDocumentMethod(JsonMap document) {
  final id = document['id'];
  if (id is! String) return false;
  try {
    buildDidResolutionUrl(id);
    if (id.startsWith('did:wba:')) return validateDidDocumentBinding(document);
    return document['verificationMethod'] is List &&
        document['authentication'] is List;
  } catch (_) {
    return false;
  }
}
