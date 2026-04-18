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
  }) =>
      generateHttpSignatureHeaders(method, url, signer, body, headers: headers);
}
