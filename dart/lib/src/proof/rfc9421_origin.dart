import 'dart:convert';

import '../authentication/types.dart';
import '../codec/canonical_json.dart';
import '../errors.dart';
import 'im.dart';

const String rfc9421OriginProofDefaultLabel = 'sig1';
const List<String> rfc9421OriginProofDefaultComponents = [
  '@method',
  '@target-uri',
  'content-digest',
];

enum TargetKind { agent, group, service }

class Rfc9421OriginProof {
  const Rfc9421OriginProof({
    required this.contentDigest,
    required this.signatureInput,
    required this.signature,
  });

  final String contentDigest;
  final String signatureInput;
  final String signature;

  JsonMap toJson() => {
    'contentDigest': contentDigest,
    'signatureInput': signatureInput,
    'signature': signature,
  };
}

class Rfc9421OriginProofGenerationOptions {
  const Rfc9421OriginProofGenerationOptions({
    this.created,
    this.expires,
    this.nonce,
    this.label,
  });

  final int? created;
  final int? expires;
  final String? nonce;
  final String? label;
}

class Rfc9421OriginProofVerificationOptions {
  const Rfc9421OriginProofVerificationOptions({
    this.didDocument,
    this.verificationMethod,
    this.expectedSignerDid,
  });

  final JsonMap? didDocument;
  final JsonMap? verificationMethod;
  final String? expectedSignerDid;
}

JsonMap buildSignedRequestObject(String method, JsonMap meta, JsonMap body) {
  if (method.trim().isEmpty) {
    throw const AnpProofException('method is required');
  }
  return {
    'method': method,
    'meta': cloneJsonMap(meta),
    'body': cloneJsonMap(body),
  };
}

List<int> canonicalizeSignedRequestObject(JsonMap value) {
  final method = value['method']?.toString() ?? '';
  if (method.trim().isEmpty) {
    throw const AnpProofException('method is required');
  }
  if (value['meta'] is! Map) {
    throw const AnpProofException('meta must be an object');
  }
  if (value['body'] is! Map) {
    throw const AnpProofException('body must be an object');
  }
  return canonicalJsonBytes(value);
}

String buildLogicalTargetUri(TargetKind targetKind, String targetDid) {
  final did = targetDid.trim();
  if (did.isEmpty) {
    throw const AnpProofException('target did is required');
  }
  return 'anp://${targetKind.name}/${_strictPercentEncode(did)}';
}

String buildRfc9421OriginSignatureBase(
  String method,
  String logicalTargetUri,
  String contentDigest,
  String signatureInput,
) {
  if (method.trim().isEmpty) {
    throw const AnpProofException('method is required');
  }
  if (logicalTargetUri.trim().isEmpty) {
    throw const AnpProofException('logical_target_uri is required');
  }
  if (contentDigest.trim().isEmpty) {
    throw const AnpProofException('content_digest is required');
  }
  final parsed = parseImSignatureInput(signatureInput);
  _validateRfc9421OriginParsedSignatureInput(parsed);
  final componentValues = <String, String>{
    '@method': method,
    '@target-uri': logicalTargetUri,
    'content-digest': contentDigest,
  };
  final lines = <String>[
    for (final component in parsed.components)
      '"$component": ${componentValues[component]}',
    '"@signature-params": ${parsed.signatureParams}',
  ];
  return lines.join('\n');
}

Future<Rfc9421OriginProof> generateRfc9421OriginProof(
  String method,
  JsonMap meta,
  JsonMap body,
  MessageSigner signer, {
  Rfc9421OriginProofGenerationOptions options =
      const Rfc9421OriginProofGenerationOptions(),
}) async {
  _validateRfc9421OriginLabel(options.label);
  final signedRequestObject = buildSignedRequestObject(method, meta, body);
  final canonicalRequest = canonicalizeSignedRequestObject(signedRequestObject);
  final logicalTargetUri = _buildLogicalTargetUriFromMeta(meta);
  final signatureInput = buildImSignatureInput(
    signer.keyId,
    label: _normalizedRfc9421OriginLabel(options.label),
    components: rfc9421OriginProofDefaultComponents,
    created: options.created,
    expires: options.expires,
    nonce: options.nonce,
  );
  final contentDigest = buildImContentDigest(canonicalRequest);
  final signatureBase = buildRfc9421OriginSignatureBase(
    method,
    logicalTargetUri,
    contentDigest,
    signatureInput,
  );
  final signatureBytes = await signer.sign(utf8.encode(signatureBase));
  final proof = Rfc9421OriginProof(
    contentDigest: contentDigest,
    signatureInput: signatureInput,
    signature: encodeImSignature(
      signatureBytes,
      label: _normalizedRfc9421OriginLabel(options.label),
    ),
  );
  _validateRfc9421OriginParsedSignatureInput(
    parseImSignatureInput(proof.signatureInput),
  );
  return proof;
}

Future<ParsedImSignatureInput> verifyRfc9421OriginProof(
  Rfc9421OriginProof originProof,
  String method,
  JsonMap meta,
  JsonMap body,
  MessageVerifier verifier, {
  Rfc9421OriginProofVerificationOptions options =
      const Rfc9421OriginProofVerificationOptions(),
}) async {
  final signedRequestObject = buildSignedRequestObject(method, meta, body);
  final canonicalRequest = canonicalizeSignedRequestObject(signedRequestObject);
  final logicalTargetUri = _buildLogicalTargetUriFromMeta(meta);
  final parsed = parseImSignatureInput(originProof.signatureInput);
  _validateRfc9421OriginParsedSignatureInput(parsed);
  if (options.expectedSignerDid != null &&
      options.expectedSignerDid!.isNotEmpty &&
      !parsed.keyId.startsWith('${options.expectedSignerDid}#')) {
    throw const AnpProofException(
      'proof keyid must belong to expected signer DID',
    );
  }
  if (!verifyImContentDigest(canonicalRequest, originProof.contentDigest)) {
    throw const AnpProofException(
      'proof contentDigest does not match request payload',
    );
  }
  final signatureBase = buildRfc9421OriginSignatureBase(
    method,
    logicalTargetUri,
    originProof.contentDigest,
    originProof.signatureInput,
  );
  final decodedSignature = decodeImSignature(originProof.signature);
  if (decodedSignature.label.isNotEmpty &&
      decodedSignature.label != parsed.label) {
    throw const AnpProofException('invalid proof.signature encoding');
  }
  final ok = await verifier.verify(
    utf8.encode(signatureBase),
    decodedSignature.signature,
    parsed.keyId,
  );
  if (!ok) {
    throw const AnpProofException('signature verification failed');
  }
  return parsed;
}

String _buildLogicalTargetUriFromMeta(JsonMap meta) {
  final target = meta['target'];
  if (target is! Map) {
    throw const AnpProofException('meta.target is required');
  }
  final kind = target['kind']?.toString().trim() ?? '';
  final did = target['did']?.toString().trim() ?? '';
  final targetKind = switch (kind) {
    'agent' => TargetKind.agent,
    'group' => TargetKind.group,
    'service' => TargetKind.service,
    _ => throw AnpProofException('unsupported target kind: $kind'),
  };
  return buildLogicalTargetUri(targetKind, did);
}

void _validateRfc9421OriginParsedSignatureInput(ParsedImSignatureInput parsed) {
  _validateRfc9421OriginLabel(parsed.label);
  if (!_sameStringList(
    parsed.components,
    rfc9421OriginProofDefaultComponents,
  )) {
    throw const AnpProofException(
      'RFC 9421 origin proof requires covered components ("@method" "@target-uri" "content-digest")',
    );
  }
}

void _validateRfc9421OriginLabel(String? label) {
  if (_normalizedRfc9421OriginLabel(label) != rfc9421OriginProofDefaultLabel) {
    throw const AnpProofException(
      'RFC 9421 origin proof requires signature label sig1',
    );
  }
}

String _normalizedRfc9421OriginLabel(String? label) {
  final normalized = label?.trim() ?? '';
  return normalized.isEmpty ? rfc9421OriginProofDefaultLabel : normalized;
}

bool _sameStringList(List<String> left, List<String> right) {
  if (left.length != right.length) return false;
  for (var index = 0; index < left.length; index++) {
    if (left[index] != right[index]) return false;
  }
  return true;
}

String _strictPercentEncode(String value) {
  final bytes = utf8.encode(value);
  final buffer = StringBuffer();
  for (final byte in bytes) {
    final isAlpha =
        (byte >= 0x41 && byte <= 0x5a) || (byte >= 0x61 && byte <= 0x7a);
    final isDigit = byte >= 0x30 && byte <= 0x39;
    final isUnreserved =
        isAlpha ||
        isDigit ||
        byte == 0x2d ||
        byte == 0x2e ||
        byte == 0x5f ||
        byte == 0x7e;
    if (isUnreserved) {
      buffer.writeCharCode(byte);
    } else {
      buffer.write('%${byte.toRadixString(16).toUpperCase().padLeft(2, '0')}');
    }
  }
  return buffer.toString();
}
