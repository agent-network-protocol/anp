import 'http_signatures.dart';
import 'did_wba.dart';
import 'types.dart';
import 'did_resource.dart';
import 'verification_methods.dart';
import 'http_auth_security.dart';
import '../errors.dart';

final _processReplayStore = MemoryHttpReplayStore();

class DidWbaVerifier {
  const DidWbaVerifier({
    required this.didDocument,
    this.replayStore,
    this.replayConsumer,
    this.verifierScope,
    this.clock,
    this.policy = const HttpSignaturePolicy(),
  });

  final JsonMap didDocument;
  final HttpReplayStore? replayStore;
  final HttpReplayConsumer? replayConsumer;
  final String? verifierScope;
  final AuthClock? clock;
  final HttpSignaturePolicy policy;

  Future<VerificationSuccess> verifyRequest(
    String method,
    String url,
    Map<String, String> headers,
    List<int> body,
    String did,
  ) async {
    if (policy.cryptoOnly ||
        !validateDidDocumentMethod(didDocument) ||
        didDocument['deactivated'] == true) {
      throw const AnpAuthenticationException(
        'invalid authentication document or policy',
      );
    }
    final snapshot = Map<String, String>.from(headers);
    final bytes = List<int>.from(body);
    if (snapshot.keys.map((key) => key.toLowerCase()).toSet().length !=
        snapshot.length) {
      throw const AnpAuthenticationException('ambiguous duplicate HTTP header');
    }
    final authorization = snapshot.entries
        .where((entry) => entry.key.toLowerCase() == 'authorization')
        .map((entry) => entry.value)
        .firstOrNull;
    if (authorization != null && authorization.startsWith('DIDWba ')) {
      return _verifyLegacy(authorization, url, did);
    }
    final metadata = await verifyHttpMessageSignature(
      didDocument: didDocument,
      requestMethod: method,
      requestUrl: url,
      headers: snapshot,
      body: bytes,
      policy: policy,
      now: (clock ?? defaultAuthClock)(),
    );
    final signer = metadata.keyId.split('#').first;
    if (did != signer ||
        didDocument['id'] != signer ||
        !isVerificationMethodAuthorized(
          didDocument,
          'authentication',
          metadata.keyId,
        )) {
      throw const AnpAuthenticationException(
        'unverified or unauthorized caller DID',
      );
    }
    final context = httpSignatureReplayContext(
      metadata,
      method,
      url,
      snapshot,
      verifierScope: verifierScope,
      policy: policy,
    );
    await _consume(context);
    return VerificationSuccess(did: signer);
  }

  Future<void> _consume(HttpReplayContext context) async {
    bool first;
    try {
      first = replayStore != null
          ? await replayStore!.consumeOnce(context)
          : replayConsumer != null
          ? await replayConsumer!(context)
          : _processReplayStore.consumeOnce(context);
    } catch (_) {
      throw const AnpAuthenticationException('replay protection unavailable');
    }
    if (!first) {
      throw const AnpAuthenticationException('HTTP signature replay detected');
    }
  }

  Future<VerificationSuccess> _verifyLegacy(
    String authorization,
    String url,
    String expectedDid,
  ) async {
    final parsed = extractAuthHeaderParts(authorization);
    final created = DateTime.tryParse(parsed.timestamp);
    if (created == null || parsed.nonce.isEmpty || parsed.nonce.length > 1024) {
      throw const AnpAuthenticationException(
        'invalid Legacy timestamp or nonce',
      );
    }
    final deadline = policy.validate(
      created.toUtc().millisecondsSinceEpoch ~/ 1000,
      null,
      (clock ?? defaultAuthClock)(),
    );
    final keyId = '${parsed.did}#${parsed.verificationMethod}';
    if (!parsed.did.startsWith('did:wba:') ||
        parsed.did != expectedDid ||
        didDocument['id'] != parsed.did ||
        !isAuthenticationAuthorized(didDocument, keyId)) {
      throw const AnpAuthenticationException(
        'unverified or unauthorized Legacy DID',
      );
    }
    final scope = verifierScope ?? authenticationOrigin(url);
    await verifyAuthHeaderSignature(
      authorization,
      didDocument,
      Uri.parse(url).host,
    );
    final context = HttpReplayContext(
      signerDid: parsed.did,
      verifierScope: scope,
      replayKey: replayDigest([
        'anp.legacy-auth.replay.v1',
        scope,
        parsed.did,
        parsed.nonce,
      ]),
      validUntil: deadline + policy.futureSkewSeconds,
    );
    await _consume(context);
    return VerificationSuccess(did: parsed.did);
  }
}
