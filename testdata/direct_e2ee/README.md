# ANP P5 direct E2EE shared vectors

These fixtures are language-neutral regression vectors for the ANP P5 private-chat E2EE SDK.

- `p5_shared_vectors.json` preserves the existing v1 cryptographic/AAD behavior.
- `p5_v2_wire_vectors.json` is a separate vNext wire-contract fixture consumed by Rust, Python, Go, and Dart. It follows `AgentNetworkProtocol@97896407a21cc5a0ea6c30908592bc41f669ac0c` and covers device-qualified Bundle/RPC/AAD/plaintext/error objects, a real Appendix-B signed Bundle, non-MTI suite preference, RFC 8785 numbers, empty JSON objects, and strict omission/null behavior without changing v1 semantics. Canonical Manifest inputs use the Messaging 1.2 mixed dependency set; the signed golden intentionally retains the complete all-v2 draft Manifest to verify temporary read compatibility without changing its historical DID binding or signature.

Normative anchors:

- `AgentNetworkProtocol/chinese/message/05-私聊端到端加密.md`: direct init AAD uses `content_type = application/anp-direct-init+json`, includes sender/recipient/profile/session/bundle/SPK fields, and omits an absent OPK field rather than serializing `null`.
- `AgentNetworkProtocol/chinese/message/05-私聊端到端加密.md`: direct cipher AAD uses `content_type = application/anp-direct-cipher+json` and does not include encrypted `application_content_type`.
- `AgentNetworkProtocol/chinese/message/05-私聊端到端加密.md`: X3DH-like initial material uses DH1/DH2/DH3 and adds DH4 when a top-level OPK is present.
- `AgentNetworkProtocol/chinese/message/05-私聊端到端加密.md`: `kdf_ck` and `kdf_rk` use the ANP Direct E2EE v1 HKDF-SHA256 labels.

`p5_shared_vectors.json` intentionally keeps only deterministic primitives and canonical AAD bytes. Full encrypted-session fixtures remain in SDK unit/integration tests because init-message encryption currently uses a fresh ephemeral key for production correctness.

The v2 fixture deliberately excludes AWiki-internal Registry/version/readiness and root-control fields. Request vectors use the SDK's transport-neutral `method` + `params` helper shape; the JSON-RPC binding layer adds `jsonrpc` and `id`. `anp_version` and `created_at` are optional outer metadata in the vector and are asserted not to affect P5 AAD. `logical_message_id` appears only in the encrypted Application Plaintext. Optional members are omitted rather than serialized as `null`.
