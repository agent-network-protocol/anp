import 'dart:async';
import 'dart:convert';

import 'package:http/http.dart' as http;

import '../errors.dart';
import 'did_wba.dart';
import 'types.dart';

Future<JsonMap> resolveDidDocument(
  String did, {
  DidResolutionOptions options = const DidResolutionOptions(),
  http.Client? client,
}) async {
  final url = _resolutionUrl(did, options.baseUrlOverride);
  final owned = client == null;
  final httpClient = client ?? http.Client();
  try {
    final response = await httpClient
        .get(Uri.parse(url), headers: options.headers)
        .timeout(options.timeout ?? const Duration(seconds: 10));
    if (response.statusCode < 200 || response.statusCode >= 300) {
      throw AnpNetworkException(
        'DID resolution failed with HTTP ${response.statusCode}',
      );
    }
    final decoded = jsonDecode(response.body);
    if (decoded is! Map) {
      throw const AnpAuthenticationException(
        'DID document response is not an object',
      );
    }
    final document = Map<String, Object?>.from(decoded.cast<String, Object?>());
    if (!validateDidDocumentBinding(document)) {
      throw const AnpAuthenticationException(
        'invalid DID WBA document binding',
      );
    }
    return document;
  } on TimeoutException catch (error) {
    throw AnpNetworkException('DID resolution timed out', cause: error);
  } finally {
    if (owned) httpClient.close();
  }
}

Future<JsonMap> resolveDidWbaDocument(
  String did, {
  DidResolutionOptions options = const DidResolutionOptions(),
  http.Client? client,
}) => resolveDidDocument(did, options: options, client: client);

String _resolutionUrl(String did, String? override) {
  if (override != null) return override;
  if (!did.startsWith('did:wba:') && !did.startsWith('did:web:')) {
    throw AnpAuthenticationException('unsupported DID method: $did');
  }
  final parts = did.split(':');
  final host = parts.length > 2 ? parts[2].replaceAll('%3A', ':') : '';
  final path = parts.length > 3
      ? '/${parts.skip(3).map(Uri.encodeComponent).join('/')}'
      : '';
  return 'https://$host$path/did.json';
}
