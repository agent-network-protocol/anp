# ANP Go SDK

Agent Network Protocol (ANP) 的纯 Go 核心 SDK 实现。

## 当前已实现

- `authentication`
  - DID WBA 文档生成
  - 旧版 DIDWba 认证头生成与验签
  - HTTP Message Signatures 生成与验签
  - `did:wba` / `did:web` 文档解析
  - 请求验证器与 Bearer Token 签发
  - 联邦请求验签辅助
- `proof`
  - W3C Data Integrity proof 生成与校验
  - 严格 Appendix-B 对象 proof 辅助
  - group receipt proof
  - did:wba binding proof
  - IM proof
- `wns`
  - handle 校验与 URI 解析
  - handle 解析
  - handle 绑定校验
- `direct_e2ee`
  - prekey bundle 辅助
  - X3DH 初始会话建立
  - 对称 ratchet 推导
  - direct init / cipher 消息处理
  - 文件存储与参考客户端辅助

## 兼容性要求

- **纯 Go 实现**
- **不使用 cgo**
- Go **1.22+**

## 模块路径

```bash
go get github.com/agent-network-protocol/anp/golang
```

## 示例

- `examples/create_did_document`
- `examples/direct_e2ee`
- `examples/proof`
- `examples/wns`

## 文档

- `docs/api.md`
- `docs/direct_e2ee-guide.md`
- `docs/release-notes.md`

## 测试

```bash
go test ./...
```
