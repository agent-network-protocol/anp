<div align="center">
  
[English](README.md) | [中文](README.cn.md)

</div>

# ANP Crawler 模块

## 模块定位
ANP Crawler 为 Agent Network Protocol (ANP) 提供了一套轻量级的发现与解析 SDK，专注于可复现的数据抓取流程，不在模块内部调用任何大模型服务，适合在生产系统或离线工具中集成使用。

## 目录结构
- `anp_client.py`：异步 HTTP 客户端，复用 `DIDWbaAuthHeader` 为外部请求附加 DID WBA 鉴权头。
- `anp_parser.py`：规范化 JSON-LD 内容，抽取 Agent Description 文档中的元数据。
- `anp_interface.py`：将接口描述（OpenRPC、JSON-RPC、自然语言描述等）转换为 OpenAI Tools 兼容的模式。
- `anp_crawler.py`：兼容性保留的旧版爬虫入口，新的代码建议直接使用上述精简类。
- `Interface.md`：关于目标数据模型与转换规则的补充说明。
- `test/`：临时用例与集成验证脚本。

仓库中的 `meta_protocol` 与 `e2e_encryption` 模块已预留好目录，但当前 ANP Crawler 的执行流程暂未使用它们。

## 基本流程
1. 使用 DID 文档与私钥实例化 `ANPClient`，从而以 DID WBA 鉴权访问受保护的 Agent 服务。
2. 调用客户端抓取智能体描述入口（JSON 或 YAML）。
3. 将响应内容交给 `ANPDocumentParser`，收集文档内容、元数据与引用的接口 URL。
4. 对每个接口文档使用 `ANPInterfaceConverter`（位于 `anp_interface.py`）转换为 OpenAI Tools 形态，供上层代理直接调用。

## 简要示例
```python
from anp.anp_crawler.anp_client import ANPClient
from anp.anp_crawler.anp_parser import ANPDocumentParser

client = ANPClient(
    did_document_path="docs/did_public/public-did-doc.json",
    private_key_path="docs/did_public/public-private-key.pem",
)

async def load_description(url: str):
    response = await client.fetch_url(url)
    if not response["success"]:
        raise RuntimeError(f"Request failed: {response['status_code']}")

    parser = ANPDocumentParser()
    content = parser.parse(response["text"], response["url"])
    return content
```

## 推荐下一步
- 参考 `examples/python/anp_crawler_examples/`，了解多跳抓取的完整流程。
- 将示例中的 DID 证书替换为自有配置，以访问私有的 Agent 注册中心。
- 如需支持更多协议格式，可在 `anp_interface.py` 中扩展转换逻辑。
