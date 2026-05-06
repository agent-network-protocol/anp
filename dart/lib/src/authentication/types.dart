import 'dart:typed_data';

import '../keys/keys.dart';

enum DidProfile { e1, k1 }

enum AuthMode { legacy, httpSignature }

const String vmKeyAuth = 'key-1';
const String vmKeyE2eeSigning = 'key-2';
const String vmKeyE2eeAgreement = 'key-3';
const String anpMessageServiceType = 'ANPMessageService';

typedef JsonMap = Map<String, Object?>;

class DidDocumentOptions {
  const DidDocumentOptions({
    this.pathSegments = const <String>[],
    this.port,
    this.didProfile = DidProfile.e1,
    this.services = const <JsonMap>[],
    this.messageServiceEndpoint,
    this.proofPurpose = 'assertionMethod',
    this.verificationMethod,
    this.domain,
    this.challenge,
    this.created,
    this.enableE2ee = true,
  });

  final List<String> pathSegments;
  final int? port;
  final DidProfile didProfile;
  final List<JsonMap> services;
  final String? messageServiceEndpoint;
  final String proofPurpose;
  final String? verificationMethod;
  final String? domain;
  final String? challenge;
  final DateTime? created;
  final bool enableE2ee;
}

class DidKeyPair {
  const DidKeyPair({
    required this.privateKey,
    required this.publicKey,
    required this.privateKeyPem,
    required this.publicKeyPem,
  });

  final PrivateKeyMaterial privateKey;
  final PublicKeyMaterial publicKey;
  final String privateKeyPem;
  final String publicKeyPem;
}

class DidDocumentBundle {
  const DidDocumentBundle({
    required this.did,
    required this.didDocument,
    required this.keys,
  });

  final String did;
  final JsonMap didDocument;
  final Map<String, DidKeyPair> keys;
}

class AnpMessageServiceOptions {
  const AnpMessageServiceOptions({
    this.routingKeys = const <String>[],
    this.accept = const <String>[],
  });

  final List<String> routingKeys;
  final List<String> accept;
}

class ParsedAuthHeader {
  const ParsedAuthHeader({
    required this.did,
    required this.nonce,
    required this.timestamp,
    required this.verificationMethod,
    required this.signature,
    this.version = '1.1',
  });

  final String did;
  final String nonce;
  final String timestamp;
  final String verificationMethod;
  final String signature;
  final String version;

  JsonMap toJson() => {
    'v': version,
    'did': did,
    'nonce': nonce,
    'timestamp': timestamp,
    'verification_method': verificationMethod,
    'signature': signature,
  };
}

class DidResolutionOptions {
  const DidResolutionOptions({
    this.baseUrlOverride,
    this.headers = const <String, String>{},
    this.timeout,
  });

  final String? baseUrlOverride;
  final Map<String, String> headers;
  final Duration? timeout;
}

class HttpSignatureOptions {
  const HttpSignatureOptions({
    this.keyId,
    this.createdSeconds,
    this.expiresSeconds,
    this.nonce,
    this.coveredComponents = const <String>[],
  });

  final String? keyId;
  final int? createdSeconds;
  final int? expiresSeconds;
  final String? nonce;
  final List<String> coveredComponents;
}

class SignatureMetadata {
  const SignatureMetadata({
    required this.keyId,
    required this.label,
    required this.signatureInput,
    required this.signature,
    this.components = const <String>[],
    this.nonce,
    this.created = 0,
    this.expires,
  });

  final String keyId;
  final String label;
  final String signatureInput;
  final Uint8List signature;
  final List<String> components;
  final String? nonce;
  final int created;
  final int? expires;
}

abstract interface class MessageSigner {
  String get keyId;
  KeyType? get keyType;
  Future<Uint8List> sign(List<int> message);
}

abstract interface class MessageVerifier {
  KeyType? keyTypeFor(String keyId) => null;
  Future<bool> verify(List<int> message, List<int> signature, String keyId);
}

class PrivateKeyMessageSigner implements MessageSigner {
  const PrivateKeyMessageSigner({
    required this.keyId,
    required this.privateKey,
  });

  @override
  final String keyId;
  final PrivateKeyMaterial privateKey;

  @override
  KeyType get keyType => privateKey.type;

  @override
  Future<Uint8List> sign(List<int> message) async => privateKey.sign(message);
}

class PublicKeyMessageVerifier implements MessageVerifier {
  const PublicKeyMessageVerifier(this.publicKeysById);

  final Map<String, PublicKeyMaterial> publicKeysById;

  @override
  KeyType? keyTypeFor(String keyId) => publicKeysById[keyId]?.type;

  @override
  Future<bool> verify(
    List<int> message,
    List<int> signature,
    String keyId,
  ) async {
    final publicKey = publicKeysById[keyId];
    return publicKey != null && publicKey.verify(message, signature);
  }
}

class VerificationSuccess {
  const VerificationSuccess({required this.did, this.token});

  final String did;
  final String? token;
}

class FederatedVerificationOptions {
  const FederatedVerificationOptions({
    this.didResolutionOptions = const DidResolutionOptions(),
  });
  final DidResolutionOptions didResolutionOptions;
}

class FederatedVerificationResult {
  const FederatedVerificationResult({
    required this.verified,
    this.did,
    this.reason,
  });
  final bool verified;
  final String? did;
  final String? reason;
}
