import '../authentication/types.dart';
import 'im.dart';

enum TargetKind { direct, group }

String buildLogicalTargetUri(TargetKind targetKind, String targetDid) =>
    'anp://${targetKind.name}/${Uri.encodeComponent(targetDid)}';

String buildRfc9421OriginSignatureBase(
  String method,
  String logicalTargetUri,
  String contentDigest,
  String signatureInput,
) =>
    '${method.toUpperCase()}\n$logicalTargetUri\n$contentDigest\n$signatureInput';

JsonMap buildSignedRequestObject(String method, JsonMap meta, JsonMap body) => {
  'method': method,
  'meta': meta,
  'body': body,
};

Future<ImProof> generateRfc9421OriginProof(
  String method,
  JsonMap meta,
  JsonMap body,
  MessageSigner signer,
) async {
  final payload = body.toString().codeUnits;
  final digest = buildImContentDigest(payload);
  final input = buildImSignatureInput(signer.keyId);
  final sig = await signer.sign(
    buildRfc9421OriginSignatureBase(
      method,
      meta['target']?.toString() ?? '',
      digest,
      input,
    ).codeUnits,
  );
  return ImProof(
    contentDigest: digest,
    signatureInput: input,
    signature: encodeImSignature(sig),
  );
}
