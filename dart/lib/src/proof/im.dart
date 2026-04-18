import '../codec/base64.dart';
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
  });
  final String label;
  final String keyId;
  final List<String> components;
}

String buildImContentDigest(List<int> payload) =>
    'sha-256=:${encodeBase64(sha256Bytes(payload))}:';

bool verifyImContentDigest(List<int> payload, String digest) =>
    buildImContentDigest(payload) == digest;

String buildImSignatureInput(
  String keyId, {
  String label = 'sig1',
  List<String> components = imProofDefaultComponents,
}) =>
    '$label=(${components.map((value) => '"$value"').join(' ')});keyid="$keyId"';

ParsedImSignatureInput parseImSignatureInput(String value) {
  final label = value.split('=').first;
  final keyId = RegExp(r'keyid="([^"]+)"').firstMatch(value)?.group(1) ?? '';
  final components =
      RegExp(r'\(([^)]+)\)')
          .firstMatch(value)
          ?.group(1)
          ?.split(' ')
          .map((part) => part.replaceAll('"', ''))
          .toList() ??
      const <String>[];
  return ParsedImSignatureInput(
    label: label,
    keyId: keyId,
    components: components,
  );
}

String encodeImSignature(List<int> signature, {String label = 'sig1'}) =>
    '$label=:${encodeBase64(signature)}:';
