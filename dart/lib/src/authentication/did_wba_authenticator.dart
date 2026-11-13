import 'http_signatures.dart';
import 'types.dart';

class DidWbaAuthenticator {
  const DidWbaAuthenticator({required this.signer});

  final MessageSigner signer;

  Future<Map<String, String>> getAuthHeaders(
    String method,
    String url,
    List<int> body, {
    Map<String, String> headers = const {},
  }) => generateHttpSignatureHeadersWithSigner(
    didDocument: const <String, Object?>{},
    requestMethod: method,
    requestUrl: url,
    sign: signer.sign,
    headers: headers,
    body: body,
    options: HttpSignatureOptions(keyId: signer.keyId),
  );
}
