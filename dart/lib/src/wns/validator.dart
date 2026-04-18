import '../errors.dart';
import 'types.dart';

final RegExp _localPart = RegExp(r'^[a-z0-9._-]{1,64}$');
final RegExp _domainLabel = RegExp(r'^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$');

bool validateLocalPart(String localPart) => _localPart.hasMatch(localPart);

ParsedWbaUri validateHandle(String handle) {
  final parts = handle.toLowerCase().split('@');
  if (parts.length != 2 ||
      !validateLocalPart(parts[0]) ||
      !_isValidDomain(parts[1])) {
    throw AnpWnsException('invalid handle: $handle');
  }
  return ParsedWbaUri(localPart: parts[0], domain: parts[1]);
}

String normalizeHandle(String handle) => validateHandle(handle).handle;

ParsedWbaUri parseWbaUri(String uri) {
  if (!uri.startsWith('wba://')) throw AnpWnsException('invalid WBA URI: $uri');
  return validateHandle(uri.substring('wba://'.length));
}

String buildResolutionUrl(String localPart, String domain) =>
    'https://$domain/.well-known/anp/wns/$localPart.json';

String buildWbaUri(String localPart, String domain) =>
    'wba://${validateHandle('$localPart@$domain').handle}';

bool _isValidDomain(String domain) =>
    domain.split('.').every(_domainLabel.hasMatch);
