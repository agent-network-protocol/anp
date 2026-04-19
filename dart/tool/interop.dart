import 'dart:convert';
import 'dart:io';

import 'package:anp/anp.dart';

Future<void> main(List<String> args) async {
  try {
    if (args.isEmpty) {
      _usage();
    }
    switch (args.first) {
      case 'did-fixture':
        _didFixture(args.skip(1).toList());
      case 'verify-key-fixture':
        _verifyKeyFixture(args.skip(1).toList());
      case 'auth-fixture':
        await _authFixture(args.skip(1).toList());
      case 'verify-auth-fixture':
        await _verifyAuthFixture(args.skip(1).toList());
      case 'proof-fixture':
        await _proofFixture(args.skip(1).toList());
      case 'verify-proof-fixture':
        await _verifyProofFixture(args.skip(1).toList());
      case 'wns-fixture':
        _wnsFixture(args.skip(1).toList());
      case 'verify-wns-fixture':
        _verifyWnsFixture(args.skip(1).toList());
      default:
        _fail('unsupported subcommand: ${args.first}');
    }
  } on _Exit {
    // exitCode already set.
  } catch (error) {
    stderr.writeln(error);
    exitCode = 1;
  }
}

void _didFixture(List<String> args) {
  final profileName = _option(args, '--profile', 'e1');
  final hostname = _option(args, '--hostname', 'example.com');
  final profile = switch (profileName) {
    'e1' => DidProfile.e1,
    'k1' => DidProfile.k1,
    _ => throw ArgumentError('unsupported profile: $profileName'),
  };
  final bundle = createDidWbaDocument(
    hostname,
    options: DidDocumentOptions(
      pathSegments: const ['user', 'interop'],
      didProfile: profile,
    ),
  );
  _writeJson({
    'profile': profileName,
    'did_document': bundle.didDocument,
    'keys': _fixtureKeys(bundle.keys),
  });
}

void _verifyKeyFixture(List<String> args) {
  final path = _option(args, '--fixture', '');
  if (path.isEmpty) {
    throw ArgumentError('--fixture is required');
  }
  final decoded = jsonDecode(File(path).readAsStringSync());
  if (decoded is! Map || decoded['keys'] is! Map) {
    throw const FormatException('fixture must contain a keys object');
  }
  final keys = Map<String, Object?>.from(
    (decoded['keys'] as Map).cast<String, Object?>(),
  );
  var count = 0;
  for (final entry in keys.entries) {
    final pair = entry.value;
    if (pair is! Map) {
      throw FormatException('${entry.key} key pair must be an object');
    }
    final pairMap = Map<String, Object?>.from(pair.cast<String, Object?>());
    final privatePem = pairMap['private_key_pem'];
    final publicPem = pairMap['public_key_pem'];
    if (privatePem is! String || publicPem is! String) {
      throw FormatException(
        '${entry.key} key pair must contain private_key_pem and public_key_pem',
      );
    }
    if (!privatePem.startsWith('-----BEGIN PRIVATE KEY-----')) {
      throw FormatException('${entry.key} private key must be PKCS#8 PEM');
    }
    if (!publicPem.startsWith('-----BEGIN PUBLIC KEY-----')) {
      throw FormatException('${entry.key} public key must be SPKI PEM');
    }
    if (privatePem.contains('ANP ') || publicPem.contains('ANP ')) {
      throw FormatException(
        '${entry.key} key pair must not use legacy ANP PEM labels',
      );
    }
    final privateKey = privateKeyFromPem(privatePem);
    final publicKey = publicKeyFromPem(publicPem);
    if (publicKey.type != KeyType.x25519) {
      final message = utf8.encode('cross-language standard pem');
      if (!publicKey.verify(message, privateKey.sign(message))) {
        throw FormatException('${entry.key} sign/verify failed');
      }
    }
    count++;
  }
  _writeJson({'verified': true, 'key_count': count});
}

Future<void> _authFixture(List<String> args) async {
  final scheme = _option(args, '--scheme', 'legacy');
  final method = _option(args, '--method', 'POST');
  final requestUrl = _option(args, '--url', 'https://api.example.com/orders');
  final body = _option(args, '--body', '{"item":"book"}');
  final serviceDomain = _option(args, '--service-domain', 'api.example.com');
  final bundle = _bundle(args);
  final privateKey = bundle.keys[vmKeyAuth]!.privateKey;
  final fixture = <String, Object?>{
    'scheme': scheme,
    'profile': _option(args, '--profile', 'e1'),
    'did_document': bundle.didDocument,
    'keys': _fixtureKeys(bundle.keys),
    'request_url': requestUrl,
    'method': method,
    'body': body,
    'service_domain': serviceDomain,
  };
  switch (scheme) {
    case 'legacy':
      fixture['authorization'] = await generateAuthHeader(
        bundle.didDocument,
        serviceDomain,
        privateKey,
      );
      fixture['auth_json'] = await generateAuthJson(
        bundle.didDocument,
        serviceDomain,
        privateKey,
      );
    case 'http':
      fixture['headers'] = await generateHttpSignatureHeaders(
        didDocument: bundle.didDocument,
        requestUrl: requestUrl,
        requestMethod: method,
        privateKey: privateKey,
        headers: const {'Content-Type': 'application/json'},
        body: utf8.encode(body),
      );
    default:
      throw ArgumentError('unsupported auth scheme: $scheme');
  }
  _writeJson(fixture);
}

Future<void> _verifyAuthFixture(List<String> args) async {
  final fixture = _readFixture(args);
  final didDocument = _jsonMap(fixture['did_document']);
  final scheme =
      fixture['scheme']?.toString() ??
      (fixture['headers'] == null ? 'legacy' : 'http');
  switch (scheme) {
    case 'legacy':
      await verifyAuthHeaderSignature(
        fixture['authorization']?.toString() ?? '',
        didDocument,
        fixture['service_domain']?.toString() ?? '',
      );
      final authJson = fixture['auth_json']?.toString();
      if (authJson != null && authJson.isNotEmpty) {
        await verifyAuthJsonSignature(
          authJson,
          didDocument,
          fixture['service_domain']?.toString() ?? '',
        );
      }
    case 'http':
      await verifyHttpMessageSignature(
        didDocument: didDocument,
        requestMethod: fixture['method']?.toString() ?? 'POST',
        requestUrl: fixture['request_url']?.toString() ?? '',
        headers: _stringMap(fixture['headers']),
        body: utf8.encode(fixture['body']?.toString() ?? ''),
      );
    default:
      throw ArgumentError('unsupported auth scheme: $scheme');
  }
  _writeJson({'verified': true, 'scheme': scheme});
}

Future<void> _proofFixture(List<String> args) async {
  final caseName = _option(args, '--case', 'w3c-ed25519');
  final type = caseName.contains('secp256k1')
      ? KeyType.secp256k1
      : KeyType.ed25519;
  final key = generatePrivateKeyMaterial(type);
  final pair = GeneratedKeyPairPem(
    privateKeyPem: key.toPem(),
    publicKeyPem: key.publicKey().toPem(),
  );
  final signer = PrivateKeyMessageSigner(
    keyId: 'did:wba:example.com:user:proof#key-1',
    privateKey: key,
  );
  final document = <String, Object?>{
    'id': 'urn:example:proof',
    'claim': 'test-data',
  };
  final signed = await generateW3cProof(document, signer, signer.keyId);
  _writeJson({
    'case': caseName,
    'document': document,
    'signed_document': signed,
    'verification_method': signer.keyId,
    'keys': {
      'key-1': {
        'private_key_pem': pair.privateKeyPem,
        'public_key_pem': pair.publicKeyPem,
      },
    },
  });
}

Future<void> _verifyProofFixture(List<String> args) async {
  final fixture = _readFixture(args);
  final signed = _jsonMap(fixture['signed_document']);
  final keys = _jsonMap(fixture['keys']);
  final pair = _jsonMap(keys['key-1']);
  final publicKey = publicKeyFromPem(pair['public_key_pem']?.toString() ?? '');
  final verifier = PublicKeyMessageVerifier({
    fixture['verification_method']?.toString() ??
            'did:wba:example.com:user:proof#key-1':
        publicKey,
  });
  if (!await verifyW3cProof(signed, verifier)) {
    throw const FormatException('proof verification failed');
  }
  _writeJson({'verified': true, 'case': fixture['case']});
}

void _wnsFixture(List<String> args) {
  final handle = normalizeHandle(
    _option(args, '--handle', 'alice.example.com'),
  );
  final parsed = validateHandle(handle);
  final did = 'did:wba:${parsed.domain}:user:${parsed.localPart}';
  final service = buildHandleServiceEntry(did, parsed.localPart, parsed.domain);
  _writeJson({
    'handle': parsed.handle,
    'uri': buildWbaUri(parsed.localPart, parsed.domain),
    'local_part': parsed.localPart,
    'domain': parsed.domain,
    'resolution_url': buildResolutionUrl(parsed.localPart, parsed.domain),
    'did': did,
    'did_document': {
      'id': did,
      'service': [service.toJson()],
    },
  });
}

void _verifyWnsFixture(List<String> args) {
  final fixture = _readFixture(args);
  final parsed = validateHandle(fixture['handle']?.toString() ?? '');
  if (buildWbaUri(parsed.localPart, parsed.domain) != fixture['uri']) {
    throw const FormatException('WBA URI mismatch');
  }
  if (extractHandleServiceFromDidDocument(
    _jsonMap(fixture['did_document']),
  ).isEmpty) {
    throw const FormatException('missing handle service');
  }
  _writeJson({'verified': true, 'handle': parsed.handle});
}

DidDocumentBundle _bundle(List<String> args) {
  final profile = switch (_option(args, '--profile', 'e1')) {
    'e1' => DidProfile.e1,
    'k1' => DidProfile.k1,
    final other => throw ArgumentError('unsupported profile: $other'),
  };
  return createDidWbaDocument(
    _option(args, '--hostname', 'example.com'),
    options: DidDocumentOptions(
      pathSegments: const ['user', 'interop'],
      didProfile: profile,
    ),
  );
}

Map<String, Object?> _readFixture(List<String> args) {
  final path = _option(args, '--fixture', '');
  if (path.isEmpty) throw ArgumentError('--fixture is required');
  final decoded = jsonDecode(File(path).readAsStringSync());
  if (decoded is! Map) throw const FormatException('fixture must be an object');
  return Map<String, Object?>.from(decoded.cast<String, Object?>());
}

Map<String, Object?> _jsonMap(Object? value) {
  if (value is! Map) throw const FormatException('expected object');
  return Map<String, Object?>.from(value.cast<String, Object?>());
}

Map<String, String> _stringMap(Object? value) => {
  for (final entry in _jsonMap(value).entries)
    entry.key: entry.value.toString(),
};

Map<String, Object?> _fixtureKeys(Map<String, DidKeyPair> keys) => {
  for (final entry in keys.entries)
    entry.key: {
      'private_key_pem': entry.value.privateKeyPem,
      'public_key_pem': entry.value.publicKeyPem,
    },
};

String _option(List<String> args, String name, String fallback) {
  for (var i = 0; i < args.length - 1; i++) {
    if (args[i] == name) {
      return args[i + 1];
    }
  }
  return fallback;
}

void _writeJson(Object? value) {
  stdout.writeln(const JsonEncoder.withIndent('  ').convert(value));
}

Never _usage() => _fail(
  'Usage: dart run tool/interop.dart <did-fixture|verify-key-fixture|auth-fixture|verify-auth-fixture|proof-fixture|verify-proof-fixture|wns-fixture|verify-wns-fixture> [options]',
);

Never _fail(String message) {
  stderr.writeln(message);
  exitCode = 1;
  throw _Exit();
}

class _Exit implements Exception {}
