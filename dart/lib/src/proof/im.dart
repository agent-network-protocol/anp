import '../codec/base64.dart';
import '../errors.dart';
import '../keys/key_material.dart';

const List<String> imProofDefaultComponents = [
  '@method',
  '@target-uri',
  'content-digest',
];
const String imProofRelationshipAuthentication = 'authentication';
const String imProofRelationshipAssertionMethod = 'assertionMethod';

class ImProof {
  const ImProof({
    required this.contentDigest,
    required this.signatureInput,
    required this.signature,
  });
  final String contentDigest;
  final String signatureInput;
  final String signature;
}

class ParsedImSignatureInput {
  const ParsedImSignatureInput({
    required this.label,
    required this.keyId,
    required this.components,
    required this.signatureParams,
    this.nonce,
    this.created,
    this.expires,
  });
  final String label;
  final String keyId;
  final List<String> components;
  final String signatureParams;
  final String? nonce;
  final int? created;
  final int? expires;
}

String buildImContentDigest(List<int> payload) =>
    'sha-256=:${encodeBase64(sha256Bytes(payload))}:';

bool verifyImContentDigest(List<int> payload, String digest) =>
    buildImContentDigest(payload) == digest;

String buildImSignatureInput(
  String keyId, {
  String label = 'sig1',
  List<String> components = imProofDefaultComponents,
  int? created,
  int? expires,
  String? nonce,
}) {
  if (keyId.trim().isEmpty) {
    throw const AnpProofException('proof.signatureInput must include keyid');
  }
  final actualLabel = label.trim().isEmpty ? 'sig1' : label.trim();
  final actualComponents = components.isEmpty
      ? imProofDefaultComponents
      : components;
  if (actualComponents.isEmpty) {
    throw const AnpProofException(
      'proof.signatureInput must include covered components',
    );
  }
  final actualCreated =
      created ?? DateTime.now().toUtc().millisecondsSinceEpoch ~/ 1000;
  final actualNonce = nonce == null || nonce.isEmpty
      ? encodeBase64Url(
          sha256Bytes(
            utf8Bytes(DateTime.now().microsecondsSinceEpoch.toString()),
          ).sublist(0, 16),
        )
      : nonce;
  final params = <String>[
    'created=$actualCreated',
    if (expires != null) 'expires=$expires',
    'nonce="$actualNonce"',
    'keyid="$keyId"',
  ];
  return '$actualLabel=(${actualComponents.map((value) => '"$value"').join(' ')});${params.join(';')}';
}

ParsedImSignatureInput parseImSignatureInput(String value) {
  final separator = value.indexOf('=');
  if (separator < 0) {
    throw const AnpProofException('invalid proof.signatureInput format');
  }
  final label = value.substring(0, separator).trim();
  final remainder = value.substring(separator + 1).trim();
  final openIndex = remainder.indexOf('(');
  final closeIndex = remainder.indexOf(')');
  if (openIndex < 0 || closeIndex <= openIndex) {
    throw const AnpProofException('invalid proof.signatureInput format');
  }
  final components = remainder
      .substring(openIndex + 1, closeIndex)
      .split(RegExp(r'\s+'))
      .where((part) => part.isNotEmpty)
      .map((part) => part.replaceAll('"', ''))
      .toList();
  if (components.isEmpty) {
    throw const AnpProofException(
      'proof.signatureInput must include covered components',
    );
  }
  final signatureParams = remainder;
  final params = _parseKvParams(
    remainder.substring(closeIndex + 1).trim().replaceFirst(RegExp(r'^;'), ''),
  );
  final keyId = params['keyid'] ?? '';
  if (keyId.isEmpty) {
    throw const AnpProofException('proof.signatureInput must include keyid');
  }
  return ParsedImSignatureInput(
    label: label,
    keyId: keyId,
    components: components,
    signatureParams: signatureParams,
    nonce: params['nonce'],
    created: int.tryParse(params['created'] ?? ''),
    expires: int.tryParse(params['expires'] ?? ''),
  );
}

String encodeImSignature(List<int> signature, {String label = 'sig1'}) =>
    '$label=:${encodeBase64(signature)}:';

({String label, List<int> signature}) decodeImSignature(String signature) {
  final trimmed = signature.trim();
  final separator = trimmed.indexOf('=:');
  if (separator >= 0) {
    final label = trimmed.substring(0, separator);
    final encoded = trimmed.substring(separator + 2);
    if (!encoded.endsWith(':')) {
      throw const AnpProofException('invalid proof.signature encoding');
    }
    return (
      label: label,
      signature: decodeBase64(encoded.substring(0, encoded.length - 1)),
    );
  }
  final bare = trimmed.replaceAll(RegExp(r'^:+|:+$'), '');
  return (label: '', signature: decodeBase64(bare));
}

Map<String, String> _parseKvParams(String value) {
  final result = <String, String>{};
  for (final part in value.split(';')) {
    final trimmed = part.trim();
    if (trimmed.isEmpty) continue;
    final separator = trimmed.indexOf('=');
    if (separator < 0) continue;
    final key = trimmed.substring(0, separator).trim();
    var rawValue = trimmed.substring(separator + 1).trim();
    if (rawValue.startsWith('"') && rawValue.endsWith('"')) {
      rawValue = rawValue.substring(1, rawValue.length - 1);
    }
    result[key] = rawValue;
  }
  return result;
}
