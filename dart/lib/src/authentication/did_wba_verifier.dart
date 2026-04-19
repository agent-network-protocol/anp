import 'http_signatures.dart';
import 'types.dart';

class DidWbaVerifier {
  const DidWbaVerifier({required this.didDocument});

  final JsonMap didDocument;

  Future<VerificationSuccess> verifyRequest(
    String method,
    String url,
    Map<String, String> headers,
    List<int> body,
    String did,
  ) async {
    await verifyHttpMessageSignature(
      didDocument: didDocument,
      requestMethod: method,
      requestUrl: url,
      headers: headers,
      body: body,
    );
    return VerificationSuccess(did: did);
  }
}
