import 'dart:convert';

import 'package:http/http.dart' as http;

import '../errors.dart';
import 'types.dart';
import 'validator.dart';

Future<HandleResolutionDocument> resolveHandle(
  String handle, {
  ResolveHandleOptions options = const ResolveHandleOptions(),
  http.Client? client,
}) async {
  final parsed = validateHandle(handle.replaceFirst(RegExp(r'^wba://'), ''));
  final normalized = parsed.handle;
  final url = options.baseUrlOverride == null
      ? buildResolutionUrl(parsed.localPart, parsed.domain)
      : '${options.baseUrlOverride!.replaceFirst(RegExp(r'/+$'), '')}/.well-known/handle/${parsed.localPart}';
  final owned = client == null;
  final httpClient = client ?? http.Client();
  try {
    final response = await httpClient
        .get(Uri.parse(url), headers: const {'Accept': 'application/json'})
        .timeout(options.timeout);
    switch (response.statusCode) {
      case 200:
        break;
      case 301:
        throw AnpWnsException("handle '$normalized' has been migrated");
      case 404:
        throw AnpWnsException("handle '$normalized' does not exist");
      case 410:
        throw AnpWnsException(
          "handle '$normalized' has been permanently revoked",
        );
      default:
        throw AnpWnsException(
          "unexpected status ${response.statusCode} resolving '$normalized': ${response.body}",
        );
    }
    final decoded = jsonDecode(response.body);
    if (decoded is! Map) {
      throw const AnpWnsException('resolution document is not an object');
    }
    final map = Map<String, Object?>.from(decoded.cast<String, Object?>());
    final responseHandle =
        map['handle']?.toString().toLowerCase() ?? normalized;
    if (responseHandle != normalized) {
      throw AnpWnsException(
        "handle mismatch: requested '$normalized', got '$responseHandle'",
      );
    }
    return HandleResolutionDocument(
      handle: normalized,
      did: map['did']?.toString() ?? '',
      status: HandleStatus.values.firstWhere(
        (s) => s.name == (map['status'] ?? 'active'),
        orElse: () => HandleStatus.active,
      ),
      didDocument: map['didDocument'] is Map
          ? Map<String, Object?>.from(
              (map['didDocument'] as Map).cast<String, Object?>(),
            )
          : null,
    );
  } finally {
    if (owned) httpClient.close();
  }
}

Future<HandleResolutionDocument> resolveHandleFromUri(
  String uri, {
  ResolveHandleOptions options = const ResolveHandleOptions(),
  http.Client? client,
}) => resolveHandle(parseWbaUri(uri).handle, options: options, client: client);
