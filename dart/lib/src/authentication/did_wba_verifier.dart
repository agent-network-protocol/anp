import 'http_signatures.dart';
import 'types.dart';

class DidWbaVerifier {
  const DidWbaVerifier({required this.verifier});

  final MessageVerifier verifier;

  Future<VerificationSuccess> verifyRequest(
    String method,
    String url,
    Map<String, String> headers,
    List<int> body,
    String did,
  ) async {
    final ok = await verifyHttpMessageSignature(
      method,
      url,
      verifier,
      headers,
      body,
    );
    if (!ok) {
      throw const FormatException('HTTP message signature verification failed');
    }
    return VerificationSuccess(did: did);
  }
}
