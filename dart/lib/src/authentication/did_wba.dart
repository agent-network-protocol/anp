import 'dart:convert';

import '../codec/base64.dart';
import '../codec/base58.dart';
import '../codec/canonical_json.dart';
import '../errors.dart';
import '../keys/keys.dart';
import '../proof/proof.dart';
import 'types.dart';
import 'http_auth_security.dart';
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
  try {
    final id = didDocument['id'];
    final methods = didDocument['verificationMethod'];
    if (id is! String ||
        !id.startsWith('did:wba:') ||
        methods is! List ||
        methods.isEmpty) {
      return false;
    }
    final last = id.split(':').last;
    final e1 = last.startsWith('e1_'), k1 = last.startsWith('k1_');
    final bound = e1 || k1;
    final rawProof = didDocument['proof'];
    if (rawProof == null) return !bound;
    if (rawProof is! Map) return false;
    final proof = Map<String, Object?>.from(rawProof.cast<String, Object?>());
    final value = proof.remove('proofValue'), vm = proof['verificationMethod'];
    if (value is! String ||
        value.isEmpty ||
        value.length > 256 ||
        vm is! String ||
        proof['proofPurpose'] != 'assertionMethod' ||
        proof['created'] is! String ||
        !isAssertionMethodAuthorized(didDocument, vm)) {
      return false;
    }
    final method = findVerificationMethod(didDocument, vm);
    if (method == null || method['controller'] != id) return false;
    final key = extractPublicKey(method);
    if (e1 &&
        (key.type != KeyType.ed25519 ||
            computeJwkFingerprint(key) != last.substring(3))) {
      return false;
    }
    if (k1 &&
        (key.type != KeyType.secp256k1 ||
            computeJwkFingerprint(key) != last.substring(3))) {
      return false;
    }
    if (proof['type'] == proofTypeDataIntegrity) {
      if (key.type == KeyType.ed25519 &&
          proof['cryptosuite'] != cryptosuiteEddsaJcs2022) {
        return false;
      }
      if (key.type == KeyType.secp256k1 &&
          proof['cryptosuite'] != cryptosuiteDidWbaSecp256k12025) {
        return false;
      }
    } else if (e1 ||
        proof['type'] != proofTypeSecp256k1 ||
        key.type != KeyType.secp256k1) {
      return false;
    }
    final unsigned = Map<String, Object?>.from(didDocument)..remove('proof');
    final input = computeW3cProofSigningInput(unsigned, proof);
    // Read existing Dart base64url proofs and protocol multibase proofs without
    // confusing a legacy base64url value whose first character happens to be z.
    if (value.startsWith('z')) {
      try {
        if (key.verify(input, decodeBase58(value.substring(1)))) return true;
      } catch (_) {}
    }
    return key.verify(input, decodeBase64Url(value));
  } catch (_) {
    return false;
  }
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
  if (authHeader.length > 16384 ||
      RegExp(r'[\x00-\x1f\x7f]').hasMatch(authHeader) ||
      !authHeader.trim().startsWith('DIDWba ')) {
    throw const AnpAuthenticationException(
      'invalid Legacy authorization header',
    );
  }
  var rest = authHeader.trim().substring(7);
  if (rest.trimRight().endsWith(',')) {
    throw const AnpAuthenticationException(
      'invalid Legacy authorization syntax',
    );
  }
  final values = <String, String>{};
  final pattern = RegExp(
    r'^\s*([A-Za-z][A-Za-z0-9_-]*)\s*=\s*"([^"\r\n]+)"\s*(?:,\s*|$)',
  );
  while (rest.isNotEmpty) {
    final match = pattern.firstMatch(rest);
    if (match == null ||
        values.containsKey(match.group(1)!.toLowerCase()) ||
        values.length >= 32) {
      throw const AnpAuthenticationException(
        'invalid or duplicate Legacy authorization field',
      );
    }
    values[match.group(1)!.toLowerCase()] = match.group(2)!;
    rest = rest.substring(match.end);
  }
  String field(String name) {
    final value = values[name];
    if (value == null || value.isEmpty) {
      throw const AnpAuthenticationException(
        'missing Legacy authorization field',
      );
    }
    return value;
  }

  if (field('nonce').length > 1024) {
    throw const AnpAuthenticationException('Legacy nonce exceeds limit');
  }
  return ParsedAuthHeader(
    did: field('did'),
    nonce: field('nonce'),
    timestamp: field('timestamp'),
    verificationMethod: field('verification_method'),
    signature: field('signature'),
    version: values['v'] ?? '1.1',
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
  final actualNonce = nonce ?? encodeBase64Url(secureAuthNonceBytes());
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
  if (did != parsed.did) {
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
