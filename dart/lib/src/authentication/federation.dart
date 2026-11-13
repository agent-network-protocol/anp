import '../errors.dart';
import 'types.dart';
import 'did_resolver.dart';
import 'http_signatures.dart';
import 'http_auth_security.dart';
import 'verification_methods.dart';

final _federationReplayStore = MemoryHttpReplayStore();

/// A sender DID string is not proof. The old sender-only call now fails closed.
/// Provided documents/receiver scope must be host-trusted resolution/context.
Future<FederatedVerificationResult> verifyFederatedHttpRequest({
  required String senderDid,
  String? requestMethod,
  String? requestUrl,
  Map<String, String>? headers,
  List<int> body = const [],
  JsonMap? senderDidDocument,
  JsonMap? serviceDidDocument,
  String? serviceId,
  String? serviceEndpoint,
  FederatedVerificationOptions options = const FederatedVerificationOptions(),
  HttpSignaturePolicy policy = const HttpSignaturePolicy(),
  AuthClock? clock,
  HttpReplayStore? replayStore,
  HttpReplayConsumer? replayConsumer,
  String? verifierScope,
}) async {
  if (requestMethod == null || requestUrl == null || headers == null) {
    return const FederatedVerificationResult(
      verified: false,
      reason: 'full_request_proof_required',
    );
  }
  if (policy.cryptoOnly) {
    return const FederatedVerificationResult(
      verified: false,
      reason: 'real_time_policy_required',
    );
  }
  final snapshot = Map<String, String>.from(headers);
  final bytes = List<int>.from(body);
  try {
    final metadata = extractSignatureMetadata(snapshot);
    final now = (clock ?? defaultAuthClock)();
    policy.validate(metadata.created, metadata.expires, now);
    final sender =
        senderDidDocument ??
        await resolveDidDocument(
          senderDid,
          options: options.didResolutionOptions,
        );
    if (sender['id'] != senderDid) {
      throw const AnpAuthenticationException('sender DID mismatch');
    }
    final rawServices = sender['service'];
    if (rawServices is! List) {
      throw const AnpAuthenticationException('missing ANPMessageService');
    }
    final selected = rawServices
        .whereType<Map<Object?, Object?>>()
        .where(
          (item) =>
              item['type'] == anpMessageServiceType &&
              (serviceId == null || item['id'] == serviceId) &&
              (serviceEndpoint == null ||
                  item['serviceEndpoint'] == serviceEndpoint),
        )
        .toList();
    if (selected.length != 1) {
      throw const AnpAuthenticationException('ambiguous ANPMessageService');
    }
    final serviceDid = selected.single['serviceDid'];
    if (serviceDid is! String ||
        metadata.keyId.split('#').first != serviceDid) {
      throw const AnpAuthenticationException('serviceDid key mismatch');
    }
    final service =
        serviceDidDocument ??
        await resolveDidDocument(
          serviceDid,
          options: options.didResolutionOptions,
        );
    if (service['id'] != serviceDid ||
        service['deactivated'] == true ||
        !isVerificationMethodAuthorized(
          service,
          'authentication',
          metadata.keyId,
        )) {
      throw const AnpAuthenticationException('unauthorized service key');
    }
    final verified = await verifyHttpMessageSignature(
      didDocument: service,
      requestMethod: requestMethod,
      requestUrl: requestUrl,
      headers: snapshot,
      body: bytes,
      policy: policy,
      now: now,
    );
    final context = httpSignatureReplayContext(
      verified,
      requestMethod,
      requestUrl,
      snapshot,
      verifierScope: verifierScope,
      policy: policy,
    );
    bool first;
    try {
      first = replayStore != null
          ? await replayStore.consumeOnce(context)
          : replayConsumer != null
          ? await replayConsumer(context)
          : _federationReplayStore.consumeOnce(context);
    } catch (_) {
      return const FederatedVerificationResult(
        verified: false,
        reason: 'replay_protection_unavailable',
      );
    }
    if (!first) {
      return const FederatedVerificationResult(
        verified: false,
        reason: 'replay_detected',
      );
    }
    return FederatedVerificationResult(
      verified: true,
      did: senderDid,
      serviceDid: serviceDid,
    );
  } on AnpNetworkException {
    return const FederatedVerificationResult(
      verified: false,
      reason: 'resolution_unavailable',
    );
  } on AnpAuthenticationException {
    return const FederatedVerificationResult(
      verified: false,
      reason: 'authentication_failed',
    );
  } on FormatException {
    return const FederatedVerificationResult(
      verified: false,
      reason: 'authentication_failed',
    );
  }
}
