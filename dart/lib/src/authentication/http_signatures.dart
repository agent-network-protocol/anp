import 'dart:typed_data';

import '../codec/base64.dart';
import '../errors.dart';
import '../keys/key_material.dart';
import 'types.dart';
import 'verification_methods.dart';

String buildContentDigest(List<int> body) =>
    'sha-256=:${encodeBase64(sha256Bytes(body))}:';

bool verifyContentDigest(List<int> body, String contentDigest) =>
    buildContentDigest(body) == contentDigest.trim();

Future<Map<String, String>> generateHttpSignatureHeaders({
  required JsonMap didDocument,
  required String requestUrl,
  required String requestMethod,
  required PrivateKeyMaterial privateKey,
  Map<String, String> headers = const <String, String>{},
  List<int> body = const <int>[],
  HttpSignatureOptions options = const HttpSignatureOptions(),
}) async {
  final keyId = options.keyId ?? _selectDefaultKeyId(didDocument);
  var covered = options.coveredComponents.isEmpty
      ? <String>['@method', '@target-uri', '@authority']
      : [...options.coveredComponents];
  final headersToSign = Map<String, String>.from(headers);
  if (body.isNotEmpty) {
    headersToSign.putIfAbsent('Content-Digest', () => buildContentDigest(body));
    headersToSign.putIfAbsent('Content-Length', () => body.length.toString());
    if (!covered.any((value) => value.toLowerCase() == 'content-digest')) {
      covered = [...covered, 'content-digest'];
    }
  }
  final created =
      options.createdSeconds ??
      DateTime.now().toUtc().millisecondsSinceEpoch ~/ 1000;
  final expires = options.expiresSeconds ?? created + 300;
  final nonce = options.nonce ?? encodeBase64Url(_nonceBytes());
  final signatureBase = _buildSignatureBase(
    covered,
    requestMethod,
    requestUrl,
    headersToSign,
    created,
    expires,
    nonce,
    keyId,
  );
  final signature = privateKey.sign(signatureBase.codeUnits);
  final result = <String, String>{
    'Signature-Input':
        'sig1=${_serializeSignatureParams(covered, created, expires, nonce, keyId)}',
    'Signature': 'sig1=:${encodeBase64(signature)}:',
  };
  final digest = _header(headersToSign, 'Content-Digest');
  if (digest != null) result['Content-Digest'] = digest;
  return result;
}

SignatureMetadata extractSignatureMetadata(Map<String, String> headers) {
  final signatureInput = _header(headers, 'Signature-Input');
  final signatureHeader = _header(headers, 'Signature');
  if (signatureInput == null || signatureHeader == null) {
    throw const AnpAuthenticationException(
      'missing Signature-Input or Signature header',
    );
  }
  final parsedInput = _parseSignatureInput(signatureInput);
  final parsedSignature = _parseSignatureHeader(signatureHeader);
  if (parsedInput.label != parsedSignature.label) {
    throw const AnpAuthenticationException('invalid signature input');
  }
  return SignatureMetadata(
    label: parsedInput.label,
    components: parsedInput.components,
    keyId: parsedInput.params['keyid'] ?? '',
    nonce: parsedInput.params['nonce'],
    created: int.parse(parsedInput.params['created'] ?? '0'),
    expires: parsedInput.params['expires'] == null
        ? null
        : int.parse(parsedInput.params['expires']!),
    signatureInput: signatureInput,
    signature: Uint8List.fromList(parsedSignature.signature),
  );
}

Future<SignatureMetadata> verifyHttpMessageSignature({
  required JsonMap didDocument,
  required String requestMethod,
  required String requestUrl,
  required Map<String, String> headers,
  required List<int> body,
}) async {
  final signatureInput = _header(headers, 'Signature-Input');
  final signatureHeader = _header(headers, 'Signature');
  if (signatureInput == null || signatureHeader == null) {
    throw const AnpAuthenticationException(
      'missing Signature-Input or Signature header',
    );
  }
  final parsedInput = _parseSignatureInput(signatureInput);
  final parsedSignature = _parseSignatureHeader(signatureHeader);
  if (parsedInput.label != parsedSignature.label) {
    throw const AnpAuthenticationException('invalid signature input');
  }
  final keyId = parsedInput.params['keyid'];
  final created = int.tryParse(parsedInput.params['created'] ?? '');
  if (keyId == null || keyId.isEmpty || created == null) {
    throw const AnpAuthenticationException('invalid signature input');
  }
  if (body.isNotEmpty ||
      parsedInput.components.any(
        (value) => value.toLowerCase() == 'content-digest',
      )) {
    final digest = _header(headers, 'Content-Digest');
    if (digest == null) {
      throw const AnpAuthenticationException('missing Content-Digest header');
    }
    if (!verifyContentDigest(body, digest)) {
      throw const AnpAuthenticationException(
        'content-digest verification failed',
      );
    }
  }
  final method = findVerificationMethod(didDocument, keyId);
  if (method == null) {
    throw const AnpAuthenticationException('verification method not found');
  }
  final publicKey = extractPublicKey(method);
  final expires = parsedInput.params['expires'] == null
      ? null
      : int.parse(parsedInput.params['expires']!);
  final signatureBase = _buildSignatureBase(
    parsedInput.components,
    requestMethod,
    requestUrl,
    headers,
    created,
    expires,
    parsedInput.params['nonce'] ?? '',
    keyId,
  );
  if (!publicKey.verify(signatureBase.codeUnits, parsedSignature.signature)) {
    throw const AnpAuthenticationException('signature verification failed');
  }
  return SignatureMetadata(
    label: parsedInput.label,
    components: parsedInput.components,
    keyId: keyId,
    nonce: parsedInput.params['nonce'],
    created: created,
    expires: expires,
    signatureInput: signatureInput,
    signature: Uint8List.fromList(parsedSignature.signature),
  );
}

String _buildSignatureBase(
  List<String> components,
  String method,
  String rawUrl,
  Map<String, String> headers,
  int created,
  int? expires,
  String nonce,
  String keyId,
) {
  final lines = <String>[];
  for (final component in components) {
    lines.add(
      '"$component": ${_componentValue(component, method, rawUrl, headers)}',
    );
  }
  lines.add(
    '"@signature-params": ${_serializeSignatureParams(components, created, expires, nonce, keyId)}',
  );
  return lines.join('\n');
}

String _componentValue(
  String component,
  String method,
  String rawUrl,
  Map<String, String> headers,
) {
  switch (component) {
    case '@method':
      return method.toUpperCase();
    case '@target-uri':
      return rawUrl;
    case '@authority':
      final uri = Uri.parse(rawUrl);
      return uri.hasPort ? '${uri.host}:${uri.port}' : uri.host;
    default:
      final value = _header(headers, component);
      if (value == null) {
        throw const AnpAuthenticationException('invalid signature input');
      }
      return value;
  }
}

String _serializeSignatureParams(
  List<String> components,
  int created,
  int? expires,
  String nonce,
  String keyId,
) {
  final quoted = components.map((component) => '"$component"').join(' ');
  final parts = <String>['created=$created'];
  if (expires != null) parts.add('expires=$expires');
  if (nonce.isNotEmpty) parts.add('nonce="$nonce"');
  parts.add('keyid="$keyId"');
  return '($quoted);${parts.join(';')}';
}

({String label, List<String> components, Map<String, String> params})
_parseSignatureInput(String value) {
  final separator = value.indexOf('=');
  if (separator < 0) {
    throw const AnpAuthenticationException('invalid signature input');
  }
  final label = value.substring(0, separator);
  final remainder = value.substring(separator + 1);
  final open = remainder.indexOf('(');
  final close = remainder.indexOf(')');
  if (open < 0 || close <= open) {
    throw const AnpAuthenticationException('invalid signature input');
  }
  final components = remainder
      .substring(open + 1, close)
      .split(RegExp(r'\s+'))
      .where((token) => token.isNotEmpty)
      .map((token) => token.replaceAll('"', ''))
      .toList();
  if (components.isEmpty) {
    throw const AnpAuthenticationException('invalid signature input');
  }
  final params = <String, String>{};
  for (final part
      in remainder
          .substring(close + 1)
          .replaceFirst(RegExp(r'^;'), '')
          .split(';')) {
    final index = part.indexOf('=');
    if (index > 0) {
      params[part.substring(0, index).toLowerCase()] = part
          .substring(index + 1)
          .replaceAll('"', '');
    }
  }
  return (label: label, components: components, params: params);
}

({String label, List<int> signature}) _parseSignatureHeader(String value) {
  final separator = value.indexOf('=');
  if (separator < 0) {
    throw const AnpAuthenticationException('invalid signature header format');
  }
  final label = value.substring(0, separator);
  final raw = value.substring(separator + 1);
  if (!raw.startsWith(':') || !raw.endsWith(':')) {
    throw const AnpAuthenticationException('invalid signature header format');
  }
  return (
    label: label,
    signature: decodeBase64(raw.substring(1, raw.length - 1)),
  );
}

String _selectDefaultKeyId(JsonMap didDocument) {
  final authentication = didDocument['authentication'];
  if (authentication is! List || authentication.isEmpty) {
    throw const AnpAuthenticationException('verification method not found');
  }
  final first = authentication.first;
  if (first is String) return first;
  if (first is Map && first['id'] is String) return first['id']! as String;
  throw const AnpAuthenticationException('verification method not found');
}

String? _header(Map<String, String> headers, String name) {
  for (final entry in headers.entries) {
    if (entry.key.toLowerCase() == name.toLowerCase()) return entry.value;
  }
  return null;
}

List<int> _nonceBytes() => List<int>.generate(
  16,
  (index) => DateTime.now().microsecondsSinceEpoch >> (index % 8) & 0xff,
);
