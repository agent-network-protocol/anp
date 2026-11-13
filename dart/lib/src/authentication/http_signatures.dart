import 'dart:convert';
import 'dart:async';
import 'http_auth_security.dart';
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
  return generateHttpSignatureHeadersWithSigner(
    didDocument: didDocument,
    requestUrl: requestUrl,
    requestMethod: requestMethod,
    sign: (bytes) => privateKey.sign(bytes),
    headers: headers,
    body: body,
    options: options,
  );
}

/// Signs with an opaque host callback; no private-key downcast is required.
Future<Map<String, String>> generateHttpSignatureHeadersWithSigner({
  required JsonMap didDocument,
  required String requestUrl,
  required String requestMethod,
  required FutureOr<Uint8List> Function(List<int>) sign,
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
  if (!covered.contains('@method') || !covered.contains('@target-uri')) {
    throw const AnpAuthenticationException('missing required signed component');
  }
  final created =
      options.createdSeconds ??
      DateTime.now().toUtc().millisecondsSinceEpoch ~/ 1000;
  final expires = options.expiresSeconds ?? created + 300;
  final nonce = options.nonce ?? encodeBase64Url(secureAuthNonceBytes());
  const HttpSignaturePolicy(
    cryptoOnly: true,
  ).validate(created, expires, created);
  if (nonce.isEmpty ||
      nonce.length > 1024 ||
      RegExp(r'[^\x20-\x7e]').hasMatch(nonce)) {
    throw const AnpAuthenticationException('invalid nonce parameter');
  }
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
  final signature = await sign(utf8.encode(signatureBase));
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
  HttpSignaturePolicy policy = const HttpSignaturePolicy(),
  int? now,
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
  if (!keyId.startsWith('did:') ||
      keyId.split('#').length != 2 ||
      keyId.endsWith('#') ||
      keyId.split('#').first != didDocument['id']) {
    throw const AnpAuthenticationException('signature keyid DID mismatch');
  }
  final expires = parsedInput.params['expires'] == null
      ? null
      : int.tryParse(parsedInput.params['expires']!);
  if (parsedInput.params.containsKey('expires') && expires == null) {
    throw const AnpAuthenticationException('invalid expires parameter');
  }
  policy.validate(created, expires, now ?? defaultAuthClock());
  final nonce = parsedInput.params['nonce'];
  if (nonce != null && (nonce.isEmpty || nonce.length > 1024)) {
    throw const AnpAuthenticationException('invalid nonce parameter');
  }
  if (!parsedInput.components.contains('@method') ||
      !parsedInput.components.contains('@target-uri') ||
      body.isNotEmpty && !parsedInput.components.contains('content-digest')) {
    throw const AnpAuthenticationException('missing required signed component');
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
  final signatureBase = _signatureBaseWithParams(
    parsedInput.components,
    requestMethod,
    requestUrl,
    headers,
    parsedInput.serialized,
  );
  final authorities = _authorityCandidates(requestUrl);
  final bases = [
    signatureBase,
    if (parsedInput.components.contains('@authority'))
      ...authorities.map(
        (authority) => _replaceAuthority(signatureBase, authority),
      ),
  ];
  if (!bases.any(
    (base) => publicKey.verify(utf8.encode(base), parsedSignature.signature),
  )) {
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

/// Derive replay state only after signature/identity/receiver checks succeed.
HttpReplayContext httpSignatureReplayContext(
  SignatureMetadata metadata,
  String method,
  String url,
  Map<String, String> headers, {
  String? verifierScope,
  HttpSignaturePolicy policy = const HttpSignaturePolicy(),
}) {
  final input = _header(headers, 'Signature-Input');
  if (input == null) {
    throw const AnpAuthenticationException('missing signature input');
  }
  final parsed = _parseSignatureInput(input);
  final base = _signatureBaseWithParams(
    parsed.components,
    method,
    url,
    headers,
    parsed.serialized,
  );
  final digest = sha256Bytes(
    utf8.encode(
      _replaceAuthority(base, authenticationOrigin(url).split("://")[1]),
    ),
  ).map((byte) => byte.toRadixString(16).padLeft(2, '0')).join();
  final signer = metadata.keyId.split('#').first;
  final scope = verifierScope ?? authenticationOrigin(url);
  final material = metadata.nonce == null
      ? 'base:$digest'
      : 'nonce:${metadata.nonce}';
  final deadline = policy.validate(
    metadata.created,
    metadata.expires,
    metadata.created,
  );
  return HttpReplayContext(
    signerDid: signer,
    verifierScope: scope,
    replayKey: replayDigest([
      'anp.http-auth.replay.v1',
      scope,
      signer,
      material,
    ]),
    validUntil: deadline + policy.futureSkewSeconds,
  );
}

String _signatureBaseWithParams(
  List<String> components,
  String method,
  String url,
  Map<String, String> headers,
  String params,
) => [
  for (final component in components)
    '"$component": ${_componentValue(component, method, url, headers)}',
  '"@signature-params": $params',
].join('\n');

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

String _replaceAuthority(String base, String authority) => base
    .split('\n')
    .map(
      (line) =>
          line.startsWith('"@authority": ') ? '"@authority": $authority' : line,
    )
    .join('\n');
List<String> _authorityCandidates(String url) {
  final origin = authenticationOrigin(url),
      suffix = url.startsWith('https://') ? ':443' : ':80';
  final values = <String>{};
  for (final authority in [
    url.split('://')[1].split(RegExp(r'[/?]')).first,
    origin.split('://')[1],
  ]) {
    for (final value in [
      authority,
      authority.endsWith(suffix)
          ? authority.substring(0, authority.length - suffix.length)
          : authority,
    ]) {
      values.add(value);
      values.add(value.replaceAll(RegExp(r'[\[\]]'), ''));
    }
  }
  return values.toList();
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
  if (nonce.isNotEmpty) parts.add('nonce=${jsonEncode(nonce)}');
  parts.add('keyid=${jsonEncode(keyId)}');
  return '($quoted);${parts.join(';')}';
}

({
  String label,
  List<String> components,
  Map<String, String> params,
  String serialized,
})
_parseSignatureInput(String value) {
  const invalid = AnpAuthenticationException(
    'invalid or ambiguous signature input',
  );
  if (value.length > 16384) throw invalid;
  final match = RegExp(
    r'^([A-Za-z0-9_-]+)=\(([^)]*)\)(.*)$',
  ).firstMatch(value.trim());
  if (match == null ||
      !RegExp(
        r'''^"[a-z0-9@!#$%&'*+.^_`|~-]+"(?: +"[a-z0-9@!#$%&'*+.^_`|~-]+")*$''',
      ).hasMatch(match[2]!)) {
    throw invalid;
  }
  final components = match[2]!
      .split(RegExp(r' +'))
      .map((token) => token.substring(1, token.length - 1))
      .toList();
  if (components.length > 32 ||
      components.toSet().length != components.length) {
    throw invalid;
  }
  final params = <String, String>{};
  var rest = match[3]!,
      serialized = '(${components.map(jsonEncode).join(' ')})';
  final parameter = RegExp(
    r'''^;([a-z*][a-z0-9_.*-]*)(?:=("(?:[\x20-\x21\x23-\x5b\x5d-\x7e]|\\["\\])*"|-?[0-9]{1,15}|\?[01]|[A-Za-z*][A-Za-z0-9!#$%&'*+.^_`|~:/-]*))?''',
  );
  while (rest.isNotEmpty) {
    final part = parameter.firstMatch(rest);
    if (part == null || params.containsKey(part[1]!) || params.length >= 32) {
      throw invalid;
    }
    final name = part[1]!, raw = part[2];
    if (const ['created', 'expires'].contains(name) &&
        (raw == null || !RegExp(r'^-?[0-9]{1,15}$').hasMatch(raw))) {
      throw invalid;
    }
    if (const ['keyid', 'nonce'].contains(name) &&
        (raw == null || !raw.startsWith('"'))) {
      throw invalid;
    }
    params[name] = raw != null && raw.startsWith('"')
        ? jsonDecode(raw) as String
        : raw ?? 'true';
    serialized += ';$name';
    if (raw != null && raw != '?1') serialized += '=$raw';
    rest = rest.substring(part.end);
  }
  return (
    label: match[1]!,
    components: components,
    params: params,
    serialized: serialized,
  );
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
  final found = headers.entries
      .where((entry) => entry.key.toLowerCase() == name.toLowerCase())
      .toList();
  if (found.length > 1) {
    throw const AnpAuthenticationException('ambiguous duplicate HTTP header');
  }
  final value = found.isEmpty ? null : found.single.value;
  if (value != null &&
      (value.length > 16384 || RegExp(r'[\r\n\x00\x7f]').hasMatch(value))) {
    throw const AnpAuthenticationException(
      'invalid or excessive HTTP authentication header',
    );
  }
  return value;
}
