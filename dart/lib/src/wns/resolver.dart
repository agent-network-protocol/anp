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
  final parsed = validateHandle(handle);
  final url =
      options.baseUrlOverride ??
      buildResolutionUrl(parsed.localPart, parsed.domain);
  final owned = client == null;
  final httpClient = client ?? http.Client();
  try {
    final response = await httpClient.get(Uri.parse(url));
    if (response.statusCode == 404) {
      throw AnpWnsException('handle not found: $handle');
    }
    final decoded = jsonDecode(response.body);
    if (decoded is! Map) {
      throw const AnpWnsException('resolution document is not an object');
    }
    final map = Map<String, Object?>.from(decoded.cast<String, Object?>());
    return HandleResolutionDocument(
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
