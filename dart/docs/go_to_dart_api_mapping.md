# Go to Dart API Mapping

The Dart API is idiomatic and does not preserve Go signatures mechanically.

## Authentication

| Go | Dart |
|---|---|
| `CreateDidWBADocument` | `createDidWbaDocument` |
| `BuildANPMessageService` | `buildAnpMessageService` |
| `BuildAgentMessageService` | `buildAgentMessageService` |
| `BuildGroupMessageService` | `buildGroupMessageService` |
| `GenerateHTTPSignatureHeaders` | `generateHttpSignatureHeaders` |
| `VerifyHTTPMessageSignature` | `verifyHttpMessageSignature` |
| `ResolveDidDocument` | `resolveDidDocument` |
| `NewDIDWbaVerifier` | `DidWbaVerifier` |
| `VerifyFederatedHTTPRequest` | `verifyFederatedHttpRequest` |

## Proof

| Go | Dart |
|---|---|
| `GenerateW3CProof` | `generateW3cProof` |
| `VerifyW3CProof` | `verifyW3cProof` |
| `VerifyW3CProofDetailed` | `verifyW3cProofDetailed` |
| `GenerateObjectProof` | `generateObjectProof` |
| `VerifyObjectProof` | `verifyObjectProof` |
| `GenerateGroupReceiptProof` | `generateGroupReceiptProof` |
| `VerifyGroupReceiptProof` | `verifyGroupReceiptProof` |
| `GenerateDidWbaBinding` | `generateDidWbaBinding` |
| `VerifyDidWbaBinding` | `verifyDidWbaBinding` |
| `BuildIMContentDigest` | `buildImContentDigest` |
| `BuildIMSignatureInput` | `buildImSignatureInput` |
| `BuildLogicalTargetURI` | `buildLogicalTargetUri` |
| `BuildRFC9421OriginSignatureBase` | `buildRfc9421OriginSignatureBase` |

## WNS

| Go | Dart |
|---|---|
| `ValidateLocalPart` | `validateLocalPart` |
| `ValidateHandle` | `validateHandle` |
| `NormalizeHandle` | `normalizeHandle` |
| `ParseWBAURI` | `parseWbaUri` |
| `BuildResolutionURL` | `buildResolutionUrl` |
| `BuildWBAURI` | `buildWbaUri` |
| `ResolveHandle` | `resolveHandle` |
| `ResolveHandleFromURI` | `resolveHandleFromUri` |
| `VerifyHandleBinding` | `verifyHandleBinding` |
| `BuildHandleServiceEntry` | `buildHandleServiceEntry` |
| `ExtractHandleServiceFromDIDDocument` | `extractHandleServiceFromDidDocument` |

## Deferred

All Go `direct_e2ee` APIs are deferred for Dart v1.


## Key persistence delta from Go v0.8.5

Go now requires standard PKCS#8/SPKI PEM at runtime and rejects legacy ANP-specific PEM labels. Dart no longer emits/accepts `ANP ... PRIVATE KEY` labels, but full Go-compatible DER encoding remains a dependency-spike follow-up.
