# ANP Go SDK API Overview

## Packages

### `authentication`

Core DID WBA and request-authentication helpers.

Key APIs:

- `CreateDidWBADocument`
- `CreateDidWBADocumentWithKeyBinding`
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
- `GenerateGroupReceiptProof`
- `VerifyGroupReceiptProof`
- `BuildIMSignatureInput`
- `GenerateIMProof`
- `VerifyIMProofWithDocument`
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

Direct end-to-end encryption helpers for `anp.direct.e2ee.v1`.

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

Common production entry points:

- `PrekeyManager.GenerateSignedPrekey`
- `PrekeyManager.BuildPrekeyBundle`
- `PrekeyManager.PublishPrekeyBundle`
- `MessageServiceDirectE2eeClient.SendText`
- `MessageServiceDirectE2eeClient.SendJSON`
- `MessageServiceDirectE2eeClient.ProcessIncoming`
- `MessageServiceDirectE2eeClient.DecryptHistoryPage`

## Compatibility Notes

- Pure Go implementation only
- No cgo
- Go 1.22+
- Current release targets Rust parity for core authentication/proof/WNS and first-pass direct E2EE helpers
