# FastANP 快速开始指南

5分钟快速上手 FastANP，构建你的第一个 ANP 智能体。

## 安装

```bash
# 进入项目目录
cd /path/to/AgentConnect

# 安装依赖（包含 FastAPI 和 Uvicorn）
uv sync --extra api

# 或使用 pip
pip install -e ".[api]"
```

## 第一步：创建智能体

创建文件 `my_agent.py`：

```python
from fastapi import FastAPI
from anp.fastanp import FastANP, Context

# 初始化 FastAPI 应用
app = FastAPI()

# 初始化 FastANP 插件
anp = FastANP(
    app=app,
    name="我的第一个智能体",
    description="这是我用 FastANP 创建的第一个智能体",
    base_url="https://example.com",
    did="did:wba:example.com:agent:my-first",
    did_document_path="docs/did_public/public-did-doc.json",
    private_key_path="docs/jwt_rs256/private_key.pem",
    public_key_path="docs/jwt_rs256/public_key.pem",
    require_auth=False  # 关闭认证以便测试
)

# 定义 ad.json 路由
@app.get("/ad.json")
def get_agent_description():
    """获取智能体描述文档"""
    ad = anp.get_common_header()
    ad["interfaces"] = [
        anp.interfaces[hello].link_summary
    ]
    return ad

# 注册一个简单的方法
@anp.interface("/info/hello.json", description="问候")
def hello(name: str) -> dict:
    """
    向指定的人问好。
    
    Args:
        name: 要问候的人的名字
    """
    return {"message": f"你好，{name}！"}

# 运行服务器
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
```

## 第二步：运行智能体

```bash
uv run python my_agent.py
```

你会看到：

```
INFO:     Started server process [12345]
INFO:     Waiting for application startup.
INFO:     Application startup complete.
INFO:     Uvicorn running on http://0.0.0.0:8000
```

## 第三步：测试智能体

### 1. 获取 Agent Description

```bash
curl http://localhost:8000/ad.json | jq
```

你会看到完整的 ANP 智能体描述文档，包括你注册的接口。

### 2. 获取 OpenRPC 文档

```bash
curl http://localhost:8000/info/hello.json | jq
```

查看 `hello` 函数的 OpenRPC 接口文档。

### 3. 调用方法（通过 JSON-RPC）

```bash
curl -X POST http://localhost:8000/rpc \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "hello",
    "params": {"name": "张三"}
  }' | jq
```

响应：

```json
{
  "jsonrpc": "2.0",
  "result": {
    "message": "你好，张三！"
  },
  "id": 1
}
```

## 第四步：添加更多功能

### 使用 Context 实现会话管理

```python
@anp.interface("/info/chat.json", description="聊天")
def chat(message: str, ctx: Context) -> dict:
    """
    带会话记忆的聊天。
    
    Args:
        message: 用户消息
        ctx: 自动注入的上下文
    """
    # 获取会话数据
    history = ctx.session.get("history", [])
    history.append({"role": "user", "content": message})
    
    # 模拟回复
    reply = f"收到消息：{message}"
    history.append({"role": "assistant", "content": reply})
    
    # 保存会话数据
    ctx.session.set("history", history)
    
    return {
        "reply": reply,
        "session_id": ctx.session.id,
        "message_count": len(history)
    }
```

调用：

```bash
curl -X POST http://localhost:8000/rpc \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": 2,
    "method": "chat",
    "params": {"message": "你好"}
  }' | jq
```

### 使用 Pydantic 模型

```python
from pydantic import BaseModel

class CalculateRequest(BaseModel):
    a: int
    b: int
    operation: str  # "add", "multiply"

@anp.interface("/info/calculate.json", description="计算器")
def calculate(request: CalculateRequest) -> dict:
    """
    简单的计算器。
    
    Args:
        request: 计算请求，包含两个数字和运算符
    """
    if request.operation == "add":
        result = request.a + request.b
    elif request.operation == "multiply":
        result = request.a * request.b
    else:
        return {"error": "不支持的运算"}
    
    return {"result": result}
```

不要忘记更新 ad.json 路由：

```python
@app.get("/ad.json")
def get_agent_description():
    ad = anp.get_common_header()
    ad["interfaces"] = [
        anp.interfaces[hello].link_summary,
        anp.interfaces[chat].link_summary,
        anp.interfaces[calculate].content,  # 嵌入式
    ]
    return ad
```

调用：

```bash
curl -X POST http://localhost:8000/rpc \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": 3,
    "method": "calculate",
    "params": {
      "request": {
        "a": 5,
        "b": 3,
        "operation": "add"
      }
    }
  }' | jq
```

### 添加自定义 Information 路由

```python
@app.get("/info/capabilities.json", tags=["information"])
def get_capabilities():
    """获取智能体能力说明"""
    return {
        "capabilities": [
            "问候",
            "聊天（带会话记忆）",
            "计算"
        ],
        "version": "1.0.0",
        "language": "中文"
    }
```

在 ad.json 中添加：

```python
@app.get("/ad.json")
def get_agent_description():
    ad = anp.get_common_header()
    
    # 添加 Information
    ad["Infomations"] = [
        {
            "type": "Information",
            "description": "智能体能力说明",
            "url": f"{anp.base_url}/info/capabilities.json"
        }
    ]
    
    # 添加 Interface
    ad["interfaces"] = [
        anp.interfaces[hello].link_summary,
        anp.interfaces[chat].link_summary,
        anp.interfaces[calculate].link_summary,
    ]
    
    return ad
```

## 核心概念

### 1. FastAPI 是主框架

```python
app = FastAPI()              # FastAPI 是主框架
anp = FastANP(app=app, ...)  # FastANP 是插件
```

### 2. 用户控制所有路由

```python
@app.get("/ad.json")           # 你定义
@app.get("/info/xxx.json")     # 你定义
# FastANP 只负责 /rpc 和 OpenRPC 文档
```

### 3. Interface 两种模式

```python
# URL 引用模式（推荐）
anp.interfaces[func].link_summary

# 嵌入模式（适用于单接口）
anp.interfaces[func].content
```

### 4. Context 自动注入

```python
def my_func(param1: str, ctx: Context) -> dict:
    # ctx 会被自动注入，不需要在 JSON-RPC 参数中传递
    session_id = ctx.session.id
    did = ctx.did
    ...
```

## 完整示例

查看 `examples/python/fastanp_examples/` 目录获取更多示例：

- **simple_agent.py** - 最小示例
- **hotel_booking_agent.py** - 完整的酒店预订智能体

## 下一步

1. 阅读 [完整文档](README.md) 了解所有功能
2. 查看 [实现总结](IMPLEMENTATION.md) 了解架构设计
3. 启用 DID WBA 认证保护你的智能体
4. 部署到生产环境

## 常见问题

### Q: 如何启用认证？

将 `require_auth=True` 并提供有效的 DID 文档和 JWT 密钥：

```python
anp = FastANP(
    app=app,
    ...,
    require_auth=True,
    did_document_path="path/to/did.json",
    private_key_path="path/to/private_key.pem",
    public_key_path="path/to/public_key.pem"
)
```

### Q: 如何自定义 JSON-RPC 端点路径？

```python
anp = FastANP(
    app=app,
    ...,
    jsonrpc_server_url="/api/rpc"  # 自定义路径
)
```

### Q: 函数名重复怎么办？

FastANP 要求所有接口函数名全局唯一。使用不同的函数名：

```python
# ❌ 错误
@anp.interface("/info/search1.json")
def search(q: str) -> dict: pass

@anp.interface("/info/search2.json")
def search(q: str) -> dict: pass  # 重复！

# ✅ 正确
@anp.interface("/info/search_products.json")
def search_products(q: str) -> dict: pass

@anp.interface("/info/search_users.json")
def search_users(q: str) -> dict: pass
```

### Q: 支持异步方法吗？

支持！只需使用 `async def`：

```python
@anp.interface("/info/async_method.json")
async def async_method(param: str) -> dict:
    result = await some_async_operation(param)
    return {"result": result}
```

### Q: 如何在 ad.json 中混合使用 link 和 embed 模式？

```python
@app.get("/ad.json")
def get_agent_description():
    ad = anp.get_common_header()
    ad["interfaces"] = [
        anp.interfaces[func1].link_summary,   # URL 引用
        anp.interfaces[func2].link_summary,   # URL 引用
        anp.interfaces[func3].content,        # 嵌入
    ]
    return ad
```

## 获取帮助

- 查看 [README.md](README.md) - 完整文档
- 查看示例代码 - `examples/python/fastanp_examples/`
- 运行测试 - `uv run pytest anp/unittest/test_fastanp.py -v`

开始构建你的 ANP 智能体吧！🚀
