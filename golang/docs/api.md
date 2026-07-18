# ANP Go SDK API Overview

## Packages

### `authentication`

Core DID WBA and request-authentication helpers.

Key APIs:

- `CreateDidWBADocument`
- `CreateDidWBADocumentWithKeyBinding` (deprecated; use `CreateDidWBADocument` with `DidDocumentOptions{DidProfile: DidProfileK1}`)
- `ComputeJWKFingerprint`
- `ComputeMultikeyFingerprint`
- `BuildANPMessageService`
- `BuildAgentMessageService`
- `BuildGroupMessageService`
- `GenerateAuthHeader`
- `GenerateAuthJSON`
- `ExtractAuthHeaderParts`
- `VerifyAuthHeaderSignature`
- `VerifyAuthJSONSignature`
- `GenerateHTTPSignatureHeaders`
- `VerifyHTTPMessageSignature`
- `ResolveDidDocument`
- `ResolveDidWBADocument`
- `NewDIDWbaVerifier`
- `VerifyFederatedHTTPRequest`

### `proof`

W3C Data Integrity and ANP proof helpers.

Key APIs:

- `GenerateW3CProof`
- `VerifyW3CProof`
- `VerifyW3CProofDetailed`
- `GenerateObjectProof`
- `VerifyObjectProof`
- `GenerateGroupReceiptProof`
- `VerifyGroupReceiptProof`
- `GenerateDidWbaBinding`
- `VerifyDidWbaBinding`
- `BuildIMSignatureInput`
- `GenerateIMProof`
- `VerifyIMProofWithDocument`
- `BuildSignedRequestObject`
- `CanonicalizeSignedRequestObject`
- `BuildLogicalTargetURI`
- `BuildRFC9421OriginSignatureBase`
- `GenerateRFC9421OriginProof`
- `VerifyRFC9421OriginProof`
- `VerifyIMProofWithDocumentForRelationship`
- `VerifyIMProofWithVerificationMethod`

### `wns`

Web Name Service helpers.

Key APIs:

- `ValidateLocalPart`
- `ValidateHandle`
- `NormalizeHandle`
- `ParseWBAURI`
- `BuildResolutionURL`
- `BuildWBAURI`
- `ResolveHandle`
- `ResolveHandleWithOptions`
- `ResolveHandleFromURI`
- `VerifyHandleBinding`
- `VerifyHandleBindingWithOptions`
- `BuildHandleServiceEntry`
- `ExtractHandleServiceFromDIDDocument`

### `direct_e2ee`

Direct end-to-end encryption helpers. Existing unprefixed APIs remain `anp.direct.e2ee.v1`; explicit `V2` types/functions provide the side-by-side `anp.direct.e2ee.v2` wire contract without sharing v1 Ratchet state.

Key APIs:

- `BuildInitAAD`
- `BuildMessageAAD`
- `SignedPrekeyFromPrivateKey`
- `BuildPrekeyBundle`
- `VerifyPrekeyBundle`
- `ExtractX25519PublicKey`
- `DeriveInitialMaterialForInitiator`
- `DeriveInitialMaterialForResponder`
- `InitialSecretKeyAndNonce`
- `DeriveChainStep`
- `EncryptWithStep`
- `DecryptWithStep`
- `DirectE2eeSession.InitiateSession`
- `DirectE2eeSession.AcceptIncomingInit`
- `DirectE2eeSession.EncryptFollowUp`
- `DirectE2eeSession.DecryptFollowUp`
- `NewPrekeyManager`
- `NewMessageServiceDirectE2eeClient`
- `NewFileSessionStore`
- `NewFileSignedPrekeyStore`
- `NewFilePendingOutboundStore`
- `BuildPrekeyBundleV2` / `VerifyPrekeyBundleV2`
- `PublishPrekeyBundleRequestV2` / `GetPrekeyBundleRequestV2`
- `ParsePublishPrekeyBundleRequestV2` / `ParseGetPrekeyBundleRequestV2`
- `DirectSendRequestV2` / `ParseDirectSendRequestV2`
- `BuildInitAADV2` / `BuildMessageAADV2`
- `CanonicalApplicationPlaintextV2`

The v2 wire parser rejects explicit `null` for omitted optional members,
preserves empty `payload`/`annotations` objects under RFC 8785 JCS, and accepts
any non-empty `preferred_suite` as a negotiation preference while continuing
to validate returned MTI Bundle/cipher suite identifiers.

Common production entry points:

- `PrekeyManager.GenerateSignedPrekey`
- `PrekeyManager.BuildPrekeyBundle`
- `PrekeyManager.PublishPrekeyBundle`
- `MessageServiceDirectE2eeClient.SendText`
- `MessageServiceDirectE2eeClient.SendJSON`
- `MessageServiceDirectE2eeClient.ProcessIncoming`
- `MessageServiceDirectE2eeClient.DecryptHistoryPage`

### `group_e2ee`

Wire models and an `ExecProvider` for `anp.group.e2ee.v1`. Real group E2EE flows are owned by the Rust `anp-mls` one-shot binary, which keeps OpenMLS private state in its local SQLite state directory and receives plaintext through stdin, not argv. PR-B1 safe leave uses hidden/test-only `group.e2ee.leave_request` control-plane objects plus owner/admin processing through an epoch-advancing remove commit; it does not make same-member local-terminal leave a service success. Contract-test artifacts are still available only when explicitly enabled for compatibility tests, and those deterministic artifacts must be marked `non_cryptographic=true` and `artifact_mode=contract-test`.

Key APIs:

- `ExecProvider.Call`
- `GroupKeyPackage`
- `GroupCipherObject`
- `GroupLeaveRequestObject`
- `GroupLeaveRequestProcessObject`
- `GroupStateRef`
- `ApplicationPlaintext`

## Compatibility Notes

- Pure Go implementation only
- No cgo
- Go 1.22+
- Current release targets Rust parity for core authentication/proof/WNS and first-pass direct E2EE helpers
