# ANP P5 direct E2EE shared vectors

These fixtures are language-neutral regression vectors for the ANP P5 private-chat E2EE implementation shared by the Go and Rust SDKs.

Normative anchors:

- `AgentNetworkProtocol/chinese/message/05-私聊端到端加密.md`: direct init AAD uses `content_type = application/anp-direct-init+json`, includes sender/recipient/profile/session/bundle/SPK fields, and omits an absent OPK field rather than serializing `null`.
- `AgentNetworkProtocol/chinese/message/05-私聊端到端加密.md`: direct cipher AAD uses `content_type = application/anp-direct-cipher+json` and does not include encrypted `application_content_type`.
- `AgentNetworkProtocol/chinese/message/05-私聊端到端加密.md`: X3DH-like initial material uses DH1/DH2/DH3 and adds DH4 when a top-level OPK is present.
- `AgentNetworkProtocol/chinese/message/05-私聊端到端加密.md`: `kdf_ck` and `kdf_rk` use the ANP Direct E2EE v1 HKDF-SHA256 labels.

`p5_shared_vectors.json` intentionally keeps only deterministic primitives and canonical AAD bytes. Full encrypted-session fixtures remain in SDK unit/integration tests because init-message encryption currently uses a fresh ephemeral key for production correctness.
