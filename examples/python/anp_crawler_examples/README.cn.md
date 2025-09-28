<div align="center">
  
[English](README.md) | [中文](README.cn.md)

</div>

# ANPCrawler示例 - AMAP服务

本目录包含使用ANPCrawler访问AMAP代理服务的示例代码。

## 文件说明

- `amap_crawler_example.py` - 完整的示例，展示所有ANPCrawler功能
- `simple_amap_example.py` - 简化示例，快速入门
- `README.md` - 本说明文件

## 前置条件

### 环境设置
```bash
# 方式一：通过pip安装
pip install agent-connect

# 方式二：源码安装（推荐开发者）
git clone https://github.com/agent-network-protocol/AgentConnect.git
cd AgentConnect
uv sync
```

### DID认证文件
确保以下文件存在：
- `docs/did_public/public-did-doc.json`
- `docs/did_public/public-private-key.pem`

## 运行示例

### 简单示例
```bash
uv run python examples/python/anp_crawler_examples/simple_amap_example.py
```

### 完整示例
```bash
uv run python examples/python/anp_crawler_examples/amap_crawler_example.py
```

## 示例功能

### 1. 获取代理描述文档
```python
# 访问URL并获取ad.json内容
content_json, interfaces_list = await crawler.fetch_text(
    "https://agent-connect.ai/agents/travel/mcp/agents/amap/ad.json"
)
```

### 2. 解析JSON-RPC接口
```python
# 自动解析接口并转换为OpenAI工具格式
tools = crawler.list_available_tools()
```

### 3. 调用JSON-RPC方法
```python
# 调用发现的工具/方法
result = await crawler.execute_tool_call(tool_name, arguments)
```

## 示例输出

运行示例后，您将看到：

1. **代理描述文档内容** - 完整的ad.json内容
2. **发现的接口** - 从代理描述中提取的JSON-RPC接口
3. **可用工具列表** - 可以调用的工具名称
4. **工具调用结果** - 实际JSON-RPC调用的返回结果

## 故障排除

### 文件不存在错误
```
FileNotFoundError: DID文档文件不存在
```
**解决方案**: 确保以下文件存在:
- `docs/did_public/public-did-doc.json`
- `docs/did_public/public-private-key.pem`

### 网络连接错误
确保您的网络可以访问 `agent-connect.ai` 域名。

### 认证失败
检查DID文档和私钥文件是否正确生成和匹配。

## 代码结构

```python
# 1. 初始化爬虫
crawler = ANPCrawler(
    did_document_path="path/to/did.json",
    private_key_path="path/to/private-key.pem"
)

# 2. 获取代理描述
content, interfaces = await crawler.fetch_text(url)

# 3. 列出工具
tools = crawler.list_available_tools()

# 4. 调用工具
result = await crawler.execute_tool_call(tool_name, arguments)
```

## 相关文档

- [ANPCrawler API文档](../../../agent_connect/anp_crawler/)
- [DID WBA认证示例](../did_wba_examples/)
- [项目根目录README](../../../README.cn.md)