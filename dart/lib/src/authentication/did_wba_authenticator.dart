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
  }) => generateHttpSignatureHeaders(
    didDocument: const <String, Object?>{},
    requestMethod: method,
    requestUrl: url,
    privateKey: (signer as PrivateKeyMessageSigner).privateKey,
    headers: headers,
    body: body,
    options: HttpSignatureOptions(keyId: signer.keyId),
  );
}
