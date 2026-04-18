import '../codec/base64.dart';
import '../keys/keys.dart';
import 'types.dart';
import 'verification_methods.dart';

DidDocumentBundle createDidWbaDocument(
  String hostname, {
  DidDocumentOptions options = const DidDocumentOptions(),
}) {
  if (hostname.isEmpty) {
    throw ArgumentError.value(hostname, 'hostname', 'must not be empty');
  }
  final auth = generateKeyPairPem(
    options.didProfile == DidProfile.k1 ? KeyType.secp256k1 : KeyType.ed25519,
  );
  final signing = generateKeyPairPem(KeyType.ed25519);
  final agreement = generateKeyPairPem(KeyType.x25519);
  final path = options.pathSegments.map(Uri.encodeComponent).join(':');
  final port = options.port == null ? '' : '%3A${options.port}';
  final did = 'did:wba:$hostname$port${path.isEmpty ? '' : ':$path'}';
  final authMethod = _verificationMethod(
    did,
    vmKeyAuth,
    auth.publicKey,
    'authentication',
  );
  final signingMethod = _verificationMethod(
    did,
    vmKeyE2eeSigning,
    signing.publicKey,
    'assertionMethod',
  );
  final agreementMethod = _verificationMethod(
    did,
    vmKeyE2eeAgreement,
    agreement.publicKey,
    'keyAgreement',
  );
  final services = <JsonMap>[
    if (options.messageServiceEndpoint != null)
      buildAnpMessageService('$did#messages', options.messageServiceEndpoint!),
    ...options.services,
  ];
  final document = <String, Object?>{
    '@context': ['https://www.w3.org/ns/did/v1'],
    'id': did,
    'verificationMethod': [authMethod, signingMethod, agreementMethod],
    'authentication': ['$did#$vmKeyAuth'],
    'assertionMethod': ['$did#$vmKeyE2eeSigning'],
    'keyAgreement': ['$did#$vmKeyE2eeAgreement'],
    if (services.isNotEmpty) 'service': services,
  };
  return DidDocumentBundle(
    did: did,
    didDocument: document,
    keys: {
      vmKeyAuth: DidKeyPair(
        privateKey: auth.privateKey,
        publicKey: auth.publicKey,
        privateKeyPem: auth.pem.privateKeyPem,
        publicKeyPem: auth.pem.publicKeyPem,
      ),
      vmKeyE2eeSigning: DidKeyPair(
        privateKey: signing.privateKey,
        publicKey: signing.publicKey,
        privateKeyPem: signing.pem.privateKeyPem,
        publicKeyPem: signing.pem.publicKeyPem,
      ),
      vmKeyE2eeAgreement: DidKeyPair(
        privateKey: agreement.privateKey,
        publicKey: agreement.publicKey,
        privateKeyPem: agreement.pem.privateKeyPem,
        publicKeyPem: agreement.pem.publicKeyPem,
      ),
    },
  );
}

JsonMap buildAnpMessageService(
  String id,
  String serviceEndpoint, {
  AnpMessageServiceOptions options = const AnpMessageServiceOptions(),
}) => {
  'id': id,
  'type': anpMessageServiceType,
  'serviceEndpoint': serviceEndpoint,
  if (options.routingKeys.isNotEmpty) 'routingKeys': options.routingKeys,
  if (options.accept.isNotEmpty) 'accept': options.accept,
};

JsonMap buildAgentMessageService(
  String did,
  String serviceEndpoint, {
  AnpMessageServiceOptions options = const AnpMessageServiceOptions(),
}) => buildAnpMessageService(
  '$did#agent-message',
  serviceEndpoint,
  options: options,
);

JsonMap buildGroupMessageService(
  String did,
  String serviceEndpoint, {
  AnpMessageServiceOptions options = const AnpMessageServiceOptions(),
}) => buildAnpMessageService(
  '$did#group-message',
  serviceEndpoint,
  options: options,
);

bool validateDidDocumentBinding(JsonMap didDocument) {
  final id = didDocument['id'];
  final methods = didDocument['verificationMethod'];
  return id is String &&
      id.startsWith('did:wba:') &&
      methods is List &&
      methods.isNotEmpty;
}

bool isAuthenticationAuthorized(
  JsonMap didDocument,
  String verificationMethodId,
) => isVerificationMethodAuthorized(
  didDocument,
  'authentication',
  verificationMethodId,
);

bool isAssertionMethodAuthorized(
  JsonMap didDocument,
  String verificationMethodId,
) => isVerificationMethodAuthorized(
  didDocument,
  'assertionMethod',
  verificationMethodId,
);

String generateAuthHeader(
  String did,
  MessageSigner signer, {
  DateTime? created,
}) {
  final timestamp = (created ?? DateTime.now().toUtc()).toIso8601String();
  final payload = '$did|${signer.keyId}|$timestamp';
  // This sync facade is for simple examples; production callers should use generateAuthJson.
  return 'DIDWba did="$did", keyId="${signer.keyId}", created="$timestamp", payload="${encodeBase64Url(payload.codeUnits)}"';
}

Future<JsonMap> generateAuthJson(
  String did,
  MessageSigner signer, {
  DateTime? created,
}) async {
  final timestamp = (created ?? DateTime.now().toUtc()).toIso8601String();
  final payload = '$did|${signer.keyId}|$timestamp';
  final signature = await signer.sign(payload.codeUnits);
  return {
    'did': did,
    'keyId': signer.keyId,
    'created': timestamp,
    'signature': encodeBase64Url(signature),
  };
}

JsonMap _verificationMethod(
  String did,
  String keyId,
  PublicKeyMaterial publicKey,
  String relationship,
) => {
  'id': '$did#$keyId',
  'type': switch (publicKey.type) {
    KeyType.ed25519 => 'Multikey',
    KeyType.x25519 => 'Multikey',
    KeyType.secp256k1 => 'EcdsaSecp256k1VerificationKey2019',
    KeyType.secp256r1 => 'JsonWebKey2020',
  },
  'controller': did,
  'publicKeyJwk': publicKeyToJwk(publicKey),
  'publicKeyMultibase': computeMultikeyFingerprint(publicKey),
  'relationship': relationship,
};
