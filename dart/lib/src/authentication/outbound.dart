import 'dart:async';
import 'dart:typed_data';
import 'package:http/http.dart' as http;
import '../errors.dart';
import 'outbound_policy.dart';
import 'outbound_stub.dart' if (dart.library.io) 'outbound_io.dart' as native;

const maxDocumentBytes = 1024 * 1024;
var _activeRequests = 0;

Future<List<int>> _readBounded(
  Stream<List<int>> stream,
  Duration timeout,
) async {
  final result = Completer<List<int>>(), bytes = BytesBuilder(copy: false);
  late StreamSubscription<List<int>> subscription;
  final timer = Timer(timeout, () {
    subscription.cancel();
    if (!result.isCompleted) {
      result.completeError(const AnpNetworkException('ANP document timeout'));
    }
  });
  subscription = stream.listen(
    (chunk) {
      if (bytes.length + chunk.length > maxDocumentBytes) {
        subscription.cancel();
        if (!result.isCompleted) {
          result.completeError(
            const AnpNetworkException('ANP response exceeds size limit'),
          );
        }
        return;
      }
      bytes.add(chunk);
    },
    onError: (Object error, StackTrace stack) {
      if (!result.isCompleted) result.completeError(error, stack);
    },
    onDone: () {
      if (!result.isCompleted) result.complete(bytes.takeBytes());
    },
  );
  try {
    return await result.future;
  } finally {
    timer.cancel();
  }
}

/// Injecting a client explicitly delegates its DNS/TLS policy to the host. The
/// SDK still validates URL scope, disables redirects and limits decoded bytes.
Future<http.Response> publicDocumentGet(
  String raw, {
  Map<String, String> headers = const {},
  Duration timeout = const Duration(seconds: 10),
  String? baseUrlOverride,
  http.Client? client,
}) async {
  final uri = validatePublicUri(raw, baseUrlOverride: baseUrlOverride);
  if (timeout <= Duration.zero) {
    throw const AnpNetworkException('invalid ANP timeout');
  }
  if (_activeRequests >= 32) {
    throw const AnpNetworkException(
      'ANP document concurrency budget exhausted',
    );
  }
  _activeRequests++;
  final owned = client == null;
  http.Client? transport;
  final watch = Stopwatch()..start();
  try {
    transport =
        client ??
        native.createPublicClient(
          timeout,
          trustedOverride: baseUrlOverride != null,
        );
    final request = http.Request('GET', uri)
      ..followRedirects = false
      ..maxRedirects = 0;
    request.headers.addAll({'Accept': 'application/json', ...headers});
    final response = await transport.send(request).timeout(timeout);
    if (response.statusCode != 200) {
      await response.stream.listen((_) {}).cancel();
      return http.Response.bytes(
        [],
        response.statusCode,
        headers: response.headers,
      );
    }
    if (response.contentLength != null &&
        response.contentLength! > maxDocumentBytes) {
      await response.stream.listen((_) {}).cancel();
      throw const AnpNetworkException('ANP response exceeds size limit');
    }
    final remaining = timeout - watch.elapsed;
    if (remaining <= Duration.zero) {
      await response.stream.listen((_) {}).cancel();
      throw const AnpNetworkException('ANP document timeout');
    }
    final body = await _readBounded(response.stream, remaining);
    return http.Response.bytes(
      body,
      response.statusCode,
      headers: response.headers,
    );
  } on TimeoutException {
    throw const AnpNetworkException('ANP document timeout');
  } finally {
    if (owned) transport?.close();
    _activeRequests--;
  }
}
