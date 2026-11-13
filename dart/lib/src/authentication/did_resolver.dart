import 'dart:async';
import 'dart:convert';

import 'package:http/http.dart' as http;

import '../errors.dart';
import 'did_resource.dart';
import 'outbound.dart';
import 'types.dart';

Future<JsonMap> resolveDidDocument(
  String did, {
  DidResolutionOptions options = const DidResolutionOptions(),
  http.Client? client,
}) async {
  final url = buildDidResolutionUrl(
    did,
    baseUrlOverride: options.baseUrlOverride,
  );
  try {
    final response = await publicDocumentGet(
      url,
      headers: options.headers,
      timeout: options.timeout ?? const Duration(seconds: 10),
      baseUrlOverride: options.baseUrlOverride,
      client: client,
    );
    if (response.statusCode != 200) {
      throw const AnpNetworkException('DID resolution requires HTTP 200');
    }
    final decoded = jsonDecode(response.body);
    if (decoded is! Map) {
      throw const AnpAuthenticationException(
        'DID document response is not an object',
      );
    }
    final document = Map<String, Object?>.from(decoded.cast<String, Object?>());
    if (document['id'] != did || !validateDidDocumentMethod(document)) {
      throw const AnpAuthenticationException(
        'invalid DID WBA document binding',
      );
    }
    return document;
  } on TimeoutException catch (error) {
    throw AnpNetworkException('DID resolution timed out', cause: error);
  }
}

Future<JsonMap> resolveDidWbaDocument(
  String did, {
  DidResolutionOptions options = const DidResolutionOptions(),
  http.Client? client,
}) => resolveDidDocument(did, options: options, client: client);
