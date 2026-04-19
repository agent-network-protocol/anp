import '../errors.dart';
import 'types.dart';

final RegExp _domainLabel = RegExp(r'^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$');

bool validateLocalPart(String localPart) {
  final normalized = localPart.toLowerCase();
  if (normalized.isEmpty || normalized.length > 63) return false;
  if (normalized.startsWith('-') ||
      normalized.endsWith('-') ||
      normalized.contains('--')) {
    return false;
  }
  for (final code in normalized.codeUnits) {
    final isLower = code >= 0x61 && code <= 0x7a;
    final isDigit = code >= 0x30 && code <= 0x39;
    if (!isLower && !isDigit && code != 0x2d) return false;
  }
  return true;
}

ParsedWbaUri validateHandle(String handle) {
  final normalized = handle.trim().toLowerCase();
  if (normalized.isEmpty) {
    throw const AnpWnsException('handle must not be empty');
  }
  final dotIndex = normalized.indexOf('.');
  if (dotIndex < 0) {
    throw AnpWnsException("handle must contain at least one dot: '$handle'");
  }
  final localPart = normalized.substring(0, dotIndex);
  final domain = normalized.substring(dotIndex + 1);
  if (localPart.isEmpty) {
    throw AnpWnsException("handle local-part is empty: '$handle'");
  }
  if (domain.isEmpty) {
    throw AnpWnsException("handle domain is empty: '$handle'");
  }
  if (!validateLocalPart(localPart)) {
    throw AnpWnsException(
      "invalid local-part '$localPart': must be 1-63 chars of a-z, 0-9, hyphen; must start/end with alnum; no consecutive hyphens",
    );
  }
  if (!_isValidDomain(domain)) {
    throw AnpWnsException("invalid domain '$domain'");
  }
  return ParsedWbaUri(localPart: localPart, domain: domain);
}

String normalizeHandle(String handle) => validateHandle(handle).handle;

ParsedWbaUri parseWbaUri(String uri) {
  if (!uri.startsWith('wba://')) {
    throw AnpWnsException("URI must start with 'wba://': '$uri'");
  }
  final handle = uri.substring('wba://'.length);
  if (handle.isEmpty) {
    throw AnpWnsException("URI contains no handle after 'wba://': '$uri'");
  }
  final parsed = validateHandle(handle);
  return ParsedWbaUri(
    localPart: parsed.localPart,
    domain: parsed.domain,
    originalUri: uri,
  );
}

String buildResolutionUrl(String localPart, String domain) =>
    'https://$domain/.well-known/handle/$localPart';

String buildWbaUri(String localPart, String domain) =>
    'wba://$localPart.$domain';

bool _isValidDomain(String domain) {
  final labels = domain.split('.');
  if (labels.length < 2) return false;
  return labels.every(_domainLabel.hasMatch);
}
