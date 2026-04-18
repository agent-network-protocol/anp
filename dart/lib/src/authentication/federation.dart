import 'types.dart';

Future<FederatedVerificationResult> verifyFederatedHttpRequest({
  required String senderDid,
}) async => FederatedVerificationResult(
  verified: senderDid.startsWith('did:'),
  did: senderDid,
  reason: senderDid.startsWith('did:') ? null : 'invalid DID',
);
