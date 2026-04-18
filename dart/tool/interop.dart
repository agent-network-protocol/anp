import 'dart:convert';
import 'dart:io';

import 'package:anp/anp.dart';

void main(List<String> args) {
  try {
    if (args.isEmpty) {
      _usage();
    }
    switch (args.first) {
      case 'did-fixture':
        _didFixture(args.skip(1).toList());
      case 'verify-key-fixture':
        _verifyKeyFixture(args.skip(1).toList());
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
  'Usage: dart run tool/interop.dart <did-fixture|verify-key-fixture> [options]',
);

Never _fail(String message) {
  stderr.writeln(message);
  exitCode = 1;
  throw _Exit();
}

class _Exit implements Exception {}
