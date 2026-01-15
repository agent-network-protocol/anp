# anpChat - ANP 协议下的 LLM 驱动聊天智能体

基于 ANP（Agent Network Protocol）和 LLM 的分布式聊天系统，包含两个相互通信的智能体（ChatA 和 ChatB），由大语言模型驱动消息生成和对话管理。

## 项目概述

**anpChat** 是一个利用 ANP 协议的去中心化聊天应用示例，展示了两个 AI 智能体如何通过 DID（Decentralized Identifier）认证进行安全通信，以及如何集成 LLM 模型实现智能对话。

### 核心特性

- **ANP 协议支持**：基于 ANP 框架构建，使用 DID 身份验证
- **LLM 驱动**：集成 OpenAI 兼容接口（默认使用 DeepSeek 模型）
- **分布式架构**：两个独立的 FastAPI 服务，分别运行在 8000 和 8001 端口
- **异步通信**：基于 async/await 的高效消息处理
- **Ed25519 签名支持**：修复了 ANP 库对 Ed25519 密钥的兼容性

## 项目结构

```
anpChat/
├── ChatA.py          # Chat Agent A - 被动接收并响应消息的智能体
├── ChatB.py          # Chat Agent B - 主动发起对话的智能体
├── did_a.json        # Agent A 的 DID 文档
├── did_b.json        # Agent B 的 DID 文档
├── private_a.pem     # Agent A 的私钥文件
├── private_b.pem     # Agent B 的私钥文件
└── README.md         # 本文件
```

## 快速开始

### 环境要求

- Python 3.8+
- pip 或 conda

### 安装依赖

```bash
pip install fastapi uvicorn openai cryptography anp
```

### 环境配置

设置 LLM API 密钥：

```bash
export OPENAI_KEY="your-api-key"
export OPENAI_API_BASE="https://api.deepseek.com"  # 可选，默认使用 OpenAI
```

### 启动服务

**启动 Chat Agent A**（端口 8000）：
```bash
python ChatA.py
```

**启动 Chat Agent B**（端口 8001）：
```bash
python ChatB.py
```

ChatB 会在启动 2 秒后自动发现 ChatA 并发起一段 4 轮的对话。

## API 端点

### Chat Agent A（端口 8000）

| 端点 | 方法 | 描述 |
|------|------|------|
| `/` | GET | 查看 Agent A 的状态信息 |
| `/health` | GET | 健康检查 |
| `/a/ad.json` | GET | ANP 广告（DID 文档） |
| `/a` | POST | ANP 接口端点 |

**状态示例：**
```json
{
  "name": "Chat Agent A",
  "did": "did:wba:example.com:chata",
  "endpoint": "/a",
  "status": "running",
  "messages_received": 5
}
```

### Chat Agent B（端口 8001）

| 端点 | 方法 | 描述 |
|------|------|------|
| `/` | GET | 查看 Agent B 的状态信息 |
| `/health` | GET | 健康检查 |
| `/b/ad.json` | GET | ANP 广告（DID 文档） |

**状态示例：**
```json
{
  "name": "Chat Agent B",
  "did": "did:wba:example.com:chatb",
  "endpoint": "/b",
  "status": "running",
  "messages_sent": 4
}
```

## 工作流程

1. **启动**：ChatA 和 ChatB 分别在各自的端口启动 FastAPI 服务
2. **发现**：ChatB 在启动后尝试 discover ChatA（通过 `/a/ad.json` 端点）
3. **初始化**：ChatB 使用 LLM 生成初始问候消息
4. **对话循环**：
   - ChatB 生成消息并发送给 ChatA
   - ChatA 使用 LLM 响应
   - ChatB 接收响应并继续对话
   - 循环持续到达到指定的轮数或连接失败

## 核心类和方法

### ChatAgentA

```python
class ChatAgentA:
    def _llm_reply(self, user_message: str) -> str
        # 使用 LLM 生成回复
    
    async def receive_message(self, message: str, remaining_turns: int) -> dict
        # ANP 接口方法，接收消息并返回回复
```

### ChatAgentB

```python
class ChatAgentB:
    def _llm_generate(self, prompt: str) -> str
        # 使用 LLM 生成新消息
    
    async def start_model_driven_chat(self, turns: int = 4)
        # 发起模型驱动的对话会话
    
    async def ensure_chat_a_connection(self)
        # 确保与 ChatA 的连接
```

## 关键实现细节

### LLM 集成

两个智能体都支持与 OpenAI 兼容的 API 进行集成：

- **ChatA**：被动模式，接收消息后生成回复
- **ChatB**：主动模式，生成消息并发送给 ChatA

### DID 认证

使用 `DIDWbaAuthHeader` 进行基于 DID 的身份验证：

```python
auth = DIDWbaAuthHeader(
    did_document_path="./did_a.json",
    private_key_path="./private_a.pem"
)
```

### Ed25519 兼容性修复

项目包含对 ANP 库 Ed25519 密钥签名的兼容性补丁：

```python
def _sign_callback_compat(self, content: bytes, method_fragment: str) -> bytes:
    private_key = self._load_private_key()
    if isinstance(private_key, Ed25519PrivateKey):
        return private_key.sign(content)
    return private_key.sign(content, ec.ECDSA(hashes.SHA256()))
```

## 配置说明

### 环境变量

| 变量 | 说明 | 默认值 |
|------|------|--------|
| `OPENAI_KEY` | LLM API 密钥 | 无（必须设置） |
| `OPENAI_API_BASE` | LLM API 地址 | OpenAI 官方 API |

### 模型配置

当前默认使用 `deepseek-chat` 模型，可通过修改代码中的 `MODEL_NAME` 变量更改。

## 常见问题

**Q: ChatB 无法发现 ChatA**
- A: 确保 ChatA 已启动且在 8000 端口运行，检查防火墙设置

**Q: LLM 调用失败**
- A: 检查 `OPENAI_KEY` 环境变量是否正确设置，确保 API 密钥有效

**Q: DID 认证出错**
- A: 确保 `did_a.json`、`did_b.json`、`private_a.pem`、`private_b.pem` 文件存在且格式正确

## 扩展和定制

### 修改对话轮数

在 [ChatB.py](ChatB.py#L194) 启动函数中修改 `turns` 参数：

```python
asyncio.create_task(chat_agent_b.start_model_driven_chat(turns=10))
```

### 自定义系统提示词

在 [ChatA.py](ChatA.py#L63) 和 [ChatB.py](ChatB.py#L70) 中修改 `system_prompt`：

```python
system_prompt = "你的自定义提示词"
```

### 集成不同的 LLM

只需修改 `_get_client()` 方法和相关的 API 调用参数。

## 许可证

MIT License

## 贡献

欢迎提交 Issue 和 Pull Request！

---

**最后更新**: 2026-01-15