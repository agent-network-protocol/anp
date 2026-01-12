<div align="center">

[English](README.md) | [中文](README.cn.md)

</div>

# ANP Crawler 模块

轻量级的 ANP（Agent Network Protocol）智能体发现与交互 SDK。

## 模块定位

**ANP Crawler 像网络爬虫一样工作** - 它爬取、解析并提取 Agent Description 文档中的可调用接口。它专注于**确定性的数据收集**——模块内部不进行任何 LLM 调用——因此可以嵌入生产服务或离线工具中使用。

> **ANPCrawler vs RemoteAgent**：ANPCrawler 是爬虫风格的客户端（爬取和解析文档），而 RemoteAgent（在 OpenANP 中）是代理风格的客户端，它将远程方法下载并转化成本地方法调用。在 LLM 工具集成或数据收集场景使用 ANPCrawler；在代码中进行智能体间通信使用 RemoteAgent。

**核心特性：**
- ✅ 爬虫风格 - 像网络爬虫一样爬取和解析 ANP 文档
- ✅ OpenAI Tools 格式 - 自动接口转换，用于 LLM 集成
- ✅ 无需 LLM - 纯确定性数据收集
- ✅ DID-WBA 认证 - 安全的智能体间通信
- ✅ 生产就绪 - 适合嵌入服务

---

## 安装

```bash
pip install anp
```

或使用 UV：
```bash
uv sync
```

---

## 快速开始

### 方式一：使用 ANPCrawler（推荐）

高级爬虫自动处理一切：

```python
import asyncio
from anp.anp_crawler import ANPCrawler

async def main():
    # 使用 DID 认证初始化爬虫
    crawler = ANPCrawler(
        did_document_path="path/to/did-doc.json",
        private_key_path="path/to/private-key.pem"
    )

    # 发现智能体并解析接口
    content, tools = await crawler.fetch_text("https://example.com/ad.json")

    # 列出可用工具
    print(f"可用工具: {crawler.list_available_tools()}")

    # 执行工具
    result = await crawler.execute_tool_call("search", {"query": "hotel"})
    print(f"结果: {result}")

asyncio.run(main())
```

### 方式二：使用 ANPClient（底层控制）

获得更多请求/响应周期的控制：

```python
import asyncio
from anp.anp_crawler import ANPClient

async def main():
    client = ANPClient(
        did_document_path="path/to/did-doc.json",
        private_key_path="path/to/private-key.pem"
    )

    # 获取并解析 URL
    response = await client.fetch("https://example.com/ad.json")
    if response["success"]:
        print(f"内容: {response['data']}")

    # 直接调用 JSON-RPC 方法
    result = await client.call_jsonrpc(
        server_url="https://example.com/rpc",
        method="search",
        params={"query": "hotel"}
    )
    print(f"结果: {result}")

asyncio.run(main())
```

---

## API 参考

### ANPCrawler

高级爬虫，用于发现和交互 ANP 智能体。

#### 构造函数

```python
ANPCrawler(
    did_document_path: str,     # DID 文档 JSON 文件路径
    private_key_path: str,      # 私钥 PEM 文件路径
    cache_enabled: bool = True  # 启用 URL 缓存（默认：True）
)
```

#### 方法

##### `fetch_text(url: str) → Tuple[Dict, List]`

获取并解析 Agent Description 或接口文档。

**参数：**
| 名称 | 类型 | 说明 |
|------|------|------|
| `url` | `str` | 要获取的 URL（ad.json 或接口文档） |

**返回值：**
```python
# content_json:
{
    "agentDescriptionURI": str,  # Agent Description URI
    "contentURI": str,           # 内容 URI（不含查询参数）
    "content": str               # 原始内容
}

# interfaces_list: OpenAI Tools 格式的接口列表
[
    {
        "type": "function",
        "function": {
            "name": "search",
            "description": "搜索项目",
            "parameters": {
                "type": "object",
                "properties": {...},
                "required": [...]
            }
        }
    }
]
```

**示例：**
```python
content, tools = await crawler.fetch_text("https://example.com/ad.json")
print(f"发现 {len(tools)} 个工具")
```

---

##### `execute_tool_call(tool_name: str, arguments: Dict) → Dict`

通过 JSON-RPC 执行已发现的工具。

**参数：**
| 名称 | 类型 | 说明 |
|------|------|------|
| `tool_name` | `str` | 工具名称（来自 `list_available_tools()`） |
| `arguments` | `Dict` | 传递给工具的参数 |

**返回值：**
```python
{
    "success": bool,           # 执行是否成功
    "result": Any,             # JSON-RPC 结果（成功时）
    "error": str,              # 错误信息（失败时）
    "url": str,                # 使用的服务器 URL
    "method": str,             # JSON-RPC 方法名
    "tool_name": str           # 工具名称
}
```

**示例：**
```python
result = await crawler.execute_tool_call("search_poi", {"query": "北京"})
if result["success"]:
    print(f"找到: {result['result']}")
```

---

##### `execute_json_rpc(endpoint: str, method: str, params: Dict, request_id: str = None) → Dict`

直接执行 JSON-RPC 调用（无需接口发现）。

**参数：**
| 名称 | 类型 | 必需 | 说明 |
|------|------|------|------|
| `endpoint` | `str` | ✓ | JSON-RPC 服务器 URL |
| `method` | `str` | ✓ | 方法名 |
| `params` | `Dict` | ✓ | 方法参数 |
| `request_id` | `str` | - | 请求 ID（未提供则自动生成） |

**返回值：**
```python
{
    "success": bool,
    "result": Any,             # JSON-RPC 结果
    "error": Dict,             # JSON-RPC 错误对象
    "endpoint": str,
    "method": str,
    "request_id": str,
    "response": dict           # 完整的 JSON-RPC 响应
}
```

**示例：**
```python
result = await crawler.execute_json_rpc(
    endpoint="https://example.com/rpc",
    method="search",
    params={"query": "hotel", "limit": 10}
)
```

---

##### `list_available_tools() → List[str]`

返回所有已发现工具的名称。

```python
tools = crawler.list_available_tools()
# ['search', 'book', 'cancel']
```

---

##### `get_tool_interface_info(tool_name: str) → Optional[Dict]`

获取特定工具的元数据。

**返回值：**
```python
{
    "tool_name": str,
    "method_name": str,
    "servers": List[Dict],
    "interface_data": Dict
}
```

---

##### 缓存管理

```python
# 检查 URL 是否已访问
crawler.is_url_visited("https://example.com/ad.json")

# 获取所有已访问的 URL
visited = crawler.get_visited_urls()

# 获取缓存大小
size = crawler.get_cache_size()

# 清空缓存
crawler.clear_cache()

# 清空工具接口
crawler.clear_tool_interfaces()
```

---

### ANPClient

带 DID-WBA 认证的底层 HTTP 客户端。

#### 构造函数

```python
ANPClient(
    did_document_path: str,    # DID 文档 JSON 文件路径
    private_key_path: str      # 私钥 PEM 文件路径
)
```

#### 方法

##### `fetch_url(url, method="GET", headers=None, params=None, body=None) → Dict`

发送带 DID-WBA 认证的 HTTP 请求。

**参数：**
| 名称 | 类型 | 必需 | 说明 |
|------|------|------|------|
| `url` | `str` | ✓ | 请求 URL |
| `method` | `str` | - | HTTP 方法（默认："GET"） |
| `headers` | `Dict` | - | 额外的请求头 |
| `params` | `Dict` | - | URL 查询参数 |
| `body` | `Dict` | - | 请求体（用于 POST/PUT） |

**返回值：**
```python
{
    "success": bool,
    "text": str,               # 响应文本
    "content_type": str,       # Content-Type 头
    "encoding": str,           # 响应编码
    "status_code": int,        # HTTP 状态码
    "url": str,                # 最终 URL（重定向后）
    "error": str               # 错误信息（失败时）
}
```

---

##### `fetch(url: str) → Dict`

简化的获取方法，返回解析后的 JSON。

**返回值：**
```python
{
    "success": bool,
    "data": Dict,              # 解析后的 JSON 数据
    "error": str               # 错误信息（失败时）
}
```

---

##### `call_jsonrpc(server_url, method, params, request_id=None) → Dict`

执行 JSON-RPC 2.0 调用。

**参数：**
| 名称 | 类型 | 必需 | 说明 |
|------|------|------|------|
| `server_url` | `str` | ✓ | JSON-RPC 端点 URL |
| `method` | `str` | ✓ | 方法名 |
| `params` | `Dict` | ✓ | 方法参数 |
| `request_id` | `str` | - | 请求 ID（自动生成） |

**返回值：**
```python
{
    "success": bool,
    "result": Any,             # JSON-RPC 结果
    "error": Dict,             # JSON-RPC 错误
    "request_id": str
}
```

**示例：**
```python
result = await client.call_jsonrpc(
    "https://example.com/rpc",
    "search",
    {"query": "Tokyo"}
)
if result["success"]:
    print(result["result"])
```

---

### ANPDocumentParser

解析 Agent Description 文档并提取接口。

```python
from anp.anp_crawler import ANPDocumentParser

parser = ANPDocumentParser()
result = parser.parse_document(
    content="...",           # 原始内容字符串
    content_type="application/json",
    source_url="https://example.com/ad.json"
)

# result["interfaces"] 包含提取的接口定义
```

---

### ANPInterfaceConverter

将接口定义转换为 OpenAI Tools 格式。

```python
from anp.anp_crawler import ANPInterfaceConverter

converter = ANPInterfaceConverter()
tool = converter.convert_to_openai_tools(interface_data)

# 返回 OpenAI Tools 格式：
# {
#     "type": "function",
#     "function": {
#         "name": "...",
#         "description": "...",
#         "parameters": {...}
#     }
# }
```

---

## 典型工作流

```
1. 初始化 ANPCrawler
   └─ 提供 DID 文档和私钥用于认证

2. 获取 Agent Description (ad.json)
   └─ crawler.fetch_text(url)
   └─ 返回内容和接口列表

3. 发现可用工具
   └─ crawler.list_available_tools()
   └─ 返回工具名称

4. 执行工具
   └─ crawler.execute_tool_call(name, args)
   └─ 或: crawler.execute_json_rpc(endpoint, method, params)

5. 处理结果
   └─ 处理成功/错误响应
```

---

## LLM 集成

ANP Crawler 自动将接口转换为 OpenAI Tools 格式：

```python
import openai
from anp.anp_crawler import ANPCrawler

async def agent_with_tools():
    # 从远程智能体发现工具
    crawler = ANPCrawler(did_doc_path, key_path)
    content, tools = await crawler.fetch_text("https://example.com/ad.json")

    # 与 OpenAI 一起使用工具
    response = openai.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": "在东京找酒店"}],
        tools=tools  # 直接使用发现的工具
    )

    # 执行工具调用
    for tool_call in response.choices[0].message.tool_calls:
        result = await crawler.execute_tool_call(
            tool_call.function.name,
            json.loads(tool_call.function.arguments)
        )
        print(f"结果: {result}")
```

---

## 模块结构

```
anp/anp_crawler/
├── __init__.py          # 公开导出
├── anp_crawler.py       # ANPCrawler - 高级爬虫
├── anp_client.py        # ANPClient - 带 DID 认证的 HTTP 客户端
├── anp_parser.py        # ANPDocumentParser - 文档解析
├── anp_interface.py     # ANPInterfaceConverter - OpenAI Tools 转换
├── Interface.md         # 数据模型文档
└── test/                # 测试用例
```

---

## 示例

查看 `examples/python/anp_crawler_examples/` 获取完整示例：

| 文件 | 说明 |
|------|------|
| `simple_amap_example.py` | AMAP 服务快速入门 |
| `amap_crawler_example.py` | 完整演示 |

```bash
# 运行简单示例
uv run python examples/python/anp_crawler_examples/simple_amap_example.py

# 运行完整示例
uv run python examples/python/anp_crawler_examples/amap_crawler_example.py
```

---

## 相关文档

- [OpenANP README](../openanp/README.cn.md) - 构建 ANP 智能体
- [DID-WBA 示例](../../examples/python/did_wba_examples/) - 身份认证
- [项目 README](../../README.cn.md) - 概览

---

## 许可证

MIT License
