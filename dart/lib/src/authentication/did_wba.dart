import 'dart:convert';

import '../codec/base64.dart';
import '../codec/canonical_json.dart';
import '../errors.dart';
import '../keys/keys.dart';
import '../proof/proof.dart';
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
  final port = options.port == null ? '' : '%3A${options.port}';
  final pathSegments = <String>[...options.pathSegments];
  if (pathSegments.isNotEmpty) {
    final fingerprint = computeJwkFingerprint(auth.publicKey);
    pathSegments.add('${options.didProfile.name}_$fingerprint');
  }
  final path = pathSegments.map(Uri.encodeComponent).join(':');
  final did = 'did:wba:$hostname$port${path.isEmpty ? '' : ':$path'}';
  final authMethod = _verificationMethod(
    did,
    vmKeyAuth,
    auth.publicKey,
    'authentication',
  );
  final signing = options.enableE2ee
      ? generateKeyPairPem(KeyType.secp256r1)
      : null;
  final agreement = options.enableE2ee
      ? generateKeyPairPem(KeyType.x25519)
      : null;
  final services = <JsonMap>[
    if (options.messageServiceEndpoint != null)
      buildAnpMessageService('$did#messages', options.messageServiceEndpoint!),
    ...options.services,
  ];
  final contexts = <String>[
    'https://www.w3.org/ns/did/v1',
    if (options.didProfile == DidProfile.e1) ...[
      'https://w3id.org/security/data-integrity/v2',
      'https://w3id.org/security/multikey/v1',
    ],
    if (options.didProfile == DidProfile.k1) ...[
      'https://w3id.org/security/suites/jws-2020/v1',
      'https://w3id.org/security/suites/secp256k1-2019/v1',
      'https://w3id.org/security/data-integrity/v2',
    ],
    if (options.enableE2ee) 'https://w3id.org/security/suites/x25519-2019/v1',
  ];
  final verificationMethods = <Object?>[
    authMethod,
    if (signing != null)
      <String, Object?>{
        'id': '$did#$vmKeyE2eeSigning',
        'type': 'EcdsaSecp256r1VerificationKey2019',
        'controller': did,
        'publicKeyJwk': publicKeyToJwk(signing.publicKey),
      },
    if (agreement != null)
      <String, Object?>{
        'id': '$did#$vmKeyE2eeAgreement',
        'type': 'X25519KeyAgreementKey2019',
        'controller': did,
        'publicKeyMultibase': x25519PublicKeyToMultibase(
          agreement.publicKey.bytes,
        ),
      },
  ];
  final document = <String, Object?>{
    '@context': contexts,
    'id': did,
    'verificationMethod': verificationMethods,
    'authentication': ['$did#$vmKeyAuth'],
    'assertionMethod': ['$did#$vmKeyAuth'],
    if (agreement != null) 'keyAgreement': ['$did#$vmKeyE2eeAgreement'],
    if (services.isNotEmpty) 'service': services,
  };
  final proofType = proofTypeDataIntegrity;
  final cryptosuite = options.didProfile == DidProfile.e1
      ? cryptosuiteEddsaJcs2022
      : cryptosuiteDidWbaSecp256k12025;
  final signedDocument = _generateW3cProofSync(
    document,
    auth.privateKey,
    options.verificationMethod ?? '$did#$vmKeyAuth',
    proofType: proofType,
    cryptosuite: cryptosuite,
    created: options.created,
    proofPurpose: options.proofPurpose,
    domain: options.domain,
    challenge: options.challenge,
  );
  return DidDocumentBundle(
    did: did,
    didDocument: signedDocument,
    keys: {
      vmKeyAuth: DidKeyPair(
        privateKey: auth.privateKey,
        publicKey: auth.publicKey,
        privateKeyPem: auth.pem.privateKeyPem,
        publicKeyPem: auth.pem.publicKeyPem,
      ),
      if (signing != null)
        vmKeyE2eeSigning: DidKeyPair(
          privateKey: signing.privateKey,
          publicKey: signing.publicKey,
          privateKeyPem: signing.pem.privateKeyPem,
          publicKeyPem: signing.pem.publicKeyPem,
        ),
      if (agreement != null)
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

JsonMap _generateW3cProofSync(
  JsonMap document,
  PrivateKeyMaterial privateKey,
  String verificationMethod, {
  required String proofType,
  required String cryptosuite,
  required String proofPurpose,
  DateTime? created,
  String? domain,
  String? challenge,
}) {
  final proof = <String, Object?>{
    'type': proofType,
    'created': _isoSeconds(created ?? DateTime.now().toUtc()),
    'verificationMethod': verificationMethod,
    'proofPurpose': proofPurpose,
    'cryptosuite': cryptosuite,
    if (domain != null) 'domain': domain,
    if (challenge != null) 'challenge': challenge,
  };
  final unsigned = Map<String, Object?>.from(document)..remove('proof');
  final signature = privateKey.sign(
    computeW3cProofSigningInput(unsigned, proof),
  );
  return {
    ...unsigned,
    'proof': {...proof, 'proofValue': encodeBase64Url(signature)},
  };
}

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

Future<String> generateAuthHeader(
  JsonMap didDocument,
  String serviceDomain,
  PrivateKeyMaterial privateKey, {
  String version = '1.1',
  String? nonce,
  String? timestamp,
}) async {
  final payload = await _generateAuthPayload(
    didDocument,
    serviceDomain,
    privateKey,
    version: version,
    nonce: nonce,
    timestamp: timestamp,
  );
  return 'DIDWba v="${payload.version}", did="${payload.did}", nonce="${payload.nonce}", timestamp="${payload.timestamp}", verification_method="${payload.verificationMethod}", signature="${payload.signature}"';
}

Future<String> generateAuthJson(
  JsonMap didDocument,
  String serviceDomain,
  PrivateKeyMaterial privateKey, {
  String version = '1.1',
  String? nonce,
  String? timestamp,
}) async {
  final payload = await _generateAuthPayload(
    didDocument,
    serviceDomain,
    privateKey,
    version: version,
    nonce: nonce,
    timestamp: timestamp,
  );
  return jsonEncode(payload.toJson());
}

ParsedAuthHeader extractAuthHeaderParts(String authHeader) {
  if (!authHeader.trim().startsWith('DIDWba')) {
    throw const AnpAuthenticationException(
      'authentication header must start with DIDWba',
    );
  }
  String field(String name) {
    final match = RegExp(
      '$name="([^"]+)"',
      caseSensitive: false,
    ).firstMatch(authHeader);
    if (match == null) {
      throw AnpAuthenticationException(
        'missing field in authorization header: $name',
      );
    }
    return match.group(1)!;
  }

  return ParsedAuthHeader(
    did: field('did'),
    nonce: field('nonce'),
    timestamp: field('timestamp'),
    verificationMethod: field('verification_method'),
    signature: field('signature'),
    version:
        RegExp(
          'v="([^"]+)"',
          caseSensitive: false,
        ).firstMatch(authHeader)?.group(1) ??
        '1.1',
  );
}

Future<void> verifyAuthHeaderSignature(
  String authHeader,
  JsonMap didDocument,
  String serviceDomain,
) async => _verifyAuthPayload(
  extractAuthHeaderParts(authHeader),
  didDocument,
  serviceDomain,
);

Future<void> verifyAuthJsonSignature(
  String authJson,
  JsonMap didDocument,
  String serviceDomain,
) async {
  final payload = jsonDecode(authJson);
  if (payload is! Map) {
    throw const AnpAuthenticationException('invalid auth JSON');
  }
  await _verifyAuthPayload(
    ParsedAuthHeader(
      did: payload['did']?.toString() ?? '',
      nonce: payload['nonce']?.toString() ?? '',
      timestamp: payload['timestamp']?.toString() ?? '',
      verificationMethod: payload['verification_method']?.toString() ?? '',
      signature: payload['signature']?.toString() ?? '',
      version: payload['v']?.toString() ?? '1.1',
    ),
    didDocument,
    serviceDomain,
  );
}

Future<ParsedAuthHeader> _generateAuthPayload(
  JsonMap didDocument,
  String serviceDomain,
  PrivateKeyMaterial privateKey, {
  required String version,
  String? nonce,
  String? timestamp,
}) async {
  final did = didDocument['id']?.toString() ?? '';
  if (did.isEmpty) {
    throw const AnpAuthenticationException('invalid DID document');
  }
  final fragment = _selectAuthenticationFragment(didDocument);
  final actualNonce = nonce ?? encodeBase64Url(_nonceBytes());
  final actualTimestamp = timestamp ?? _isoSeconds(DateTime.now().toUtc());
  final payload = <String, Object?>{
    'nonce': actualNonce,
    'timestamp': actualTimestamp,
    _domainFieldForVersion(version): serviceDomain,
    'did': did,
  };
  final contentHash = sha256Bytes(canonicalJsonBytes(payload));
  return ParsedAuthHeader(
    did: did,
    nonce: actualNonce,
    timestamp: actualTimestamp,
    verificationMethod: fragment,
    signature: encodeBase64Url(privateKey.sign(contentHash)),
    version: version.isEmpty ? '1.1' : version,
  );
}

Future<void> _verifyAuthPayload(
  ParsedAuthHeader parsed,
  JsonMap didDocument,
  String serviceDomain,
) async {
  final did = didDocument['id']?.toString() ?? '';
  if (did.toLowerCase() != parsed.did.toLowerCase()) {
    throw const AnpAuthenticationException('verification failed');
  }
  final payload = <String, Object?>{
    'nonce': parsed.nonce,
    'timestamp': parsed.timestamp,
    _domainFieldForVersion(parsed.version): serviceDomain,
    'did': parsed.did,
  };
  final methodId = '${parsed.did}#${parsed.verificationMethod}';
  final method = findVerificationMethod(didDocument, methodId);
  if (method == null) {
    throw const AnpAuthenticationException('verification method not found');
  }
  final publicKey = extractPublicKey(method);
  if (!publicKey.verify(
    sha256Bytes(canonicalJsonBytes(payload)),
    decodeBase64Url(parsed.signature),
  )) {
    throw const AnpAuthenticationException('verification failed');
  }
}

String _selectAuthenticationFragment(JsonMap didDocument) {
  final auth = didDocument['authentication'];
  if (auth is! List || auth.isEmpty) {
    throw const AnpAuthenticationException('invalid DID document');
  }
  final first = auth.first;
  final id = first is String
      ? first
      : first is Map
      ? first['id']?.toString()
      : null;
  if (id == null || id.isEmpty) {
    throw const AnpAuthenticationException('invalid DID document');
  }
  return id.split('#').last;
}

String _domainFieldForVersion(String version) {
  if (version.isEmpty) return 'aud';
  final parsed = double.tryParse(version);
  if (parsed == null) return 'service';
  return parsed >= 1.1 ? 'aud' : 'service';
}

String _isoSeconds(DateTime value) =>
    value.toUtc().toIso8601String().replaceFirst(RegExp(r'\.\d+Z$'), 'Z');

List<int> _nonceBytes() => List<int>.generate(
  16,
  (index) => DateTime.now().microsecondsSinceEpoch >> (index % 8) & 0xff,
);

JsonMap _verificationMethod(
  String did,
  String keyId,
  PublicKeyMaterial publicKey,
  String relationship,
) {
  final method = <String, Object?>{
    'id': '$did#$keyId',
    'type': switch (publicKey.type) {
      KeyType.ed25519 => 'Multikey',
      KeyType.x25519 => 'X25519KeyAgreementKey2019',
      KeyType.secp256k1 => 'EcdsaSecp256k1VerificationKey2019',
      KeyType.secp256r1 => 'EcdsaSecp256r1VerificationKey2019',
    },
    'controller': did,
  };
  switch (publicKey.type) {
    case KeyType.ed25519:
      method['publicKeyMultibase'] = ed25519PublicKeyToMultibase(
        publicKey.bytes,
      );
    case KeyType.x25519:
      method['publicKeyMultibase'] = x25519PublicKeyToMultibase(
        publicKey.bytes,
      );
    case KeyType.secp256k1:
    case KeyType.secp256r1:
      method['publicKeyJwk'] = publicKeyToJwk(publicKey);
  }
  return method;
}
