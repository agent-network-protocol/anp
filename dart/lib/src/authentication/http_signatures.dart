import '../codec/base64.dart';
import '../keys/key_material.dart';
import 'types.dart';

String buildContentDigest(List<int> body) =>
    'sha-256=:${encodeBase64(sha256Bytes(body))}:';

bool verifyContentDigest(List<int> body, String contentDigest) =>
    buildContentDigest(body) == contentDigest;

Future<Map<String, String>> generateHttpSignatureHeaders(
  String requestMethod,
  String requestUrl,
  MessageSigner signer,
  List<int> body, {
  Map<String, String> headers = const <String, String>{},
  HttpSignatureOptions options = const HttpSignatureOptions(),
}) async {
  final digest = buildContentDigest(body);
  final created =
      (options.created ?? DateTime.now().toUtc()).millisecondsSinceEpoch ~/
      1000;
  final keyId = options.keyId ?? signer.keyId;
  final signatureInput =
      '${options.label}=("@method" "@target-uri" "content-digest");created=$created;keyid="$keyId"';
  final base =
      '${requestMethod.toUpperCase()}\n$requestUrl\n$digest\n$signatureInput';
  final signature = await signer.sign(base.codeUnits);
  return {
    ...headers,
    'Content-Digest': digest,
    'Signature-Input': signatureInput,
    'Signature': '${options.label}=:${encodeBase64(signature)}:',
  };
}

SignatureMetadata extractSignatureMetadata(Map<String, String> headers) {
  final input = headers['Signature-Input'] ?? headers['signature-input'];
  final signature = headers['Signature'] ?? headers['signature'];
  if (input == null || signature == null) {
    throw const FormatException('missing HTTP signature headers');
  }
  final label = input.split('=').first;
  final keyId = RegExp(r'keyid="([^"]+)"').firstMatch(input)?.group(1) ?? '';
  final sig = RegExp(r'=:([^:]+):').firstMatch(signature)?.group(1) ?? '';
  return SignatureMetadata(
    keyId: keyId,
    label: label,
    signatureInput: input,
    signature: decodeBase64(sig),
  );
}

Future<bool> verifyHttpMessageSignature(
  String requestMethod,
  String requestUrl,
  MessageVerifier verifier,
  Map<String, String> headers,
  List<int> body,
) async {
  final metadata = extractSignatureMetadata(headers);
  final digest = headers['Content-Digest'] ?? headers['content-digest'];
  if (digest == null || !verifyContentDigest(body, digest)) return false;
  final base =
      '${requestMethod.toUpperCase()}\n$requestUrl\n$digest\n${metadata.signatureInput}';
  return verifier.verify(base.codeUnits, metadata.signature, metadata.keyId);
}
