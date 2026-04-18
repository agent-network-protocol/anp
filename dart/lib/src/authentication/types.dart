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
  });

  final List<String> pathSegments;
  final int? port;
  final DidProfile didProfile;
  final List<JsonMap> services;
  final String? messageServiceEndpoint;
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
    this.created,
    this.expires,
    this.nonce,
    this.label = 'sig1',
  });

  final String? keyId;
  final DateTime? created;
  final DateTime? expires;
  final String? nonce;
  final String label;
}

class SignatureMetadata {
  const SignatureMetadata({
    required this.keyId,
    required this.label,
    required this.signatureInput,
    required this.signature,
  });

  final String keyId;
  final String label;
  final String signatureInput;
  final Uint8List signature;
}

abstract interface class MessageSigner {
  String get keyId;
  Future<Uint8List> sign(List<int> message);
}

abstract interface class MessageVerifier {
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
  Future<Uint8List> sign(List<int> message) async => privateKey.sign(message);
}

class PublicKeyMessageVerifier implements MessageVerifier {
  const PublicKeyMessageVerifier(this.publicKeysById);

  final Map<String, PublicKeyMaterial> publicKeysById;

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
