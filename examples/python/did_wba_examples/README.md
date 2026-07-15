<div align="center">

[English](README.md) | [中文](README.cn.md)

</div>

# DID-WBA Authentication Examples

This directory intentionally keeps a small set of examples for the current
Python DID-WBA flow. New integrations should use e1 identities and HTTP Message
Signatures; legacy k1 and `Authorization: DIDWba` behavior remains covered by
the SDK tests rather than separate runnable examples.

## Examples

| Goal | Program |
|---|---|
| Create current e1 DID material | `create_did_document.py` |
| Validate generated DID material | `validate_did_document.py` |
| Run complete e1 authentication and token reuse | `e1_authenticate_and_verify.py` |

For FastAPI middleware integration, challenge handling, production DID
publication, and configuration details, see
[DID_WBA_AUTH_GUIDE.en.md](DID_WBA_AUTH_GUIDE.en.md).

## Setup

From a source checkout:

```bash
uv sync
```

The complete authentication example is self-contained. It generates disposable
DID and JWT keys in a temporary directory and does not use the repository's old
shared test identity.

## Create an e1 DID

```bash
uv run python examples/python/did_wba_examples/create_did_document.py
```

The current creation example explicitly uses `did_profile="e1"` and writes:

```text
examples/python/did_wba_examples/generated/e1/did.json
examples/python/did_wba_examples/generated/e1/key-1_private.pem
examples/python/did_wba_examples/generated/e1/key-1_public.pem
```

The generated DID has an `e1_` identifier, Ed25519 authentication key, and an
`eddsa-jcs-2022` Data Integrity proof.

## Validate the DID

```bash
uv run python examples/python/did_wba_examples/validate_did_document.py
```

## Run complete authentication

```bash
uv run python examples/python/did_wba_examples/e1_authenticate_and_verify.py
```

The program demonstrates:

1. e1 DID and Ed25519 authentication-key creation.
2. DID document binding and proof validation.
3. HTTP Message Signatures request authentication.
4. RS256 Bearer token issuance and caching.
5. A second request authenticated with the cached token.

Expected output:

```text
Created e1 DID: did:wba:example.com:agents:alice:e1_<fingerprint>
DID document proof: eddsa-jcs-2022
Request authentication: http_signatures
Issued and cached Bearer token: True
Bearer token authentication: bearer
Authenticated DID: did:wba:example.com:agents:alice:e1_<fingerprint>
```
