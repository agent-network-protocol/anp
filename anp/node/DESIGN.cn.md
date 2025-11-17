# ANP 节点设计提案

## 概述

本文档提出了统一 **ANP 节点** 的设计方案，该节点可以同时作为 **服务器**（接收请求）和 **客户端**（向其他节点发送请求）运行。这种双模式能力使得代理网络协议（ANP）生态系统能够实现真正的点对点代理通信。

## 动机

### 当前状态

ANP 代码库目前包含以下独立组件：
- **FastANP**：用于构建接收请求的代理的服务器端框架
- **ANPClient**：用于向其他代理发送请求的客户端 HTTP 客户端
- **ANPCrawler**：使用 ANPClient 进行发现和交互的工具

### 问题

开发者必须手动组合这些组件来创建既能：
1. 提供服务（服务器模式）
2. 消费其他代理的服务（客户端模式）

的代理，这导致：
- 代码重复
- 设置复杂
- 身份管理不一致
- 生命周期管理困难

### 解决方案

统一的 **ANPNode** 类，它：
- 结合服务器和客户端能力
- 在两种模式间共享身份（DID）
- 提供单一、清晰的 API
- 自动管理生命周期

## 架构设计

### 高层架构

```
┌─────────────────────────────────────────┐
│           ANPNode                       │
│                                         │
│  ┌───────────────────────────────────┐  │
│  │     身份与配置                     │  │
│  │  - DID 文档                       │  │
│  │  - 私钥                           │  │
│  │  - 代理域名                       │  │
│  │  - 端口/地址                      │  │
│  └───────────────────────────────────┘  │
│                                         │
│  ┌──────────────────┐  ┌──────────────┐ │
│  │  服务器组件       │  │  客户端组件   │ │
│  │  (基于 FastANP)  │  │(基于 ANPClient)│ │
│  │                  │  │                │ │
│  │  - FastAPI 应用  │  │  - HTTP 客户端 │ │
│  │  - 接口注册      │  │  - DID 认证   │ │
│  │  - JSON-RPC      │  │  - 连接池    │ │
│  │  - 认证中间件     │ │  - 服务发现   │ │
│  └──────────────────┘  └──────────────┘ │
│                                         │
│  ┌───────────────────────────────────┐  │
│  │     共享服务                      │  │
│  │  - 日志记录                       │  │
│  │  - 指标监控                       │  │
│  │  - 错误处理                       │  │
│  └───────────────────────────────────┘  │
└─────────────────────────────────────────┘
```

### 组件详情

#### 1. 身份与配置

**目的**：节点身份的唯一真实来源

**组件**：
- DID 文档路径
- 私钥路径
- 代理域名（例如：`https://example.com`）
- 服务器端口和主机
- 功能开关（server_enabled, client_enabled）

**设计**：
```python
class NodeConfig:
    did_document_path: str
    private_key_path: str
    agent_domain: str
    host: str = "0.0.0.0"
    port: int = 8000
    server_enabled: bool = True
    client_enabled: bool = True
    auth_config: Optional[DidWbaVerifierConfig] = None
```

#### 2. 服务器组件

**目的**：处理来自其他节点的传入请求

**基于**：FastANP 框架

**功能**：
- FastAPI 应用
- 通过装饰器注册接口
- JSON-RPC 端点（`/rpc`）
- DID WBA 认证中间件
- 上下文注入
- OpenRPC 文档生成
- 代理描述（`/ad.json`）

**API**：
```python
@node.interface("/info/search.json", description="搜索项目")
def search(query: str, limit: int = 10, ctx: Context = None) -> dict:
    """搜索项目。"""
    return {"results": [...]}
```

#### 3. 客户端组件

**目的**：向其他节点发送请求

**基于**：ANPClient 及其增强功能

**功能**：
- 带 DID 认证的 HTTP 客户端
- 连接池
- 接口发现和缓存
- 请求/响应处理
- 错误处理和重试
- 超时管理

**API**：
```python
# 调用远程接口
result = await node.call_interface(
    target_did="did:wba:other.com:node:2",
    method="get_data",
    params={"id": 123}
)

# 或使用已发现的接口
interface = await node.discover_interface(target_did, "get_data")
result = await interface.execute({"id": 123})
```

#### 4. 共享服务

**目的**：两个组件共同使用的功能

**服务**：
- **日志记录**：带节点身份的统一日志
- **指标监控**：两种模式的请求/响应指标
- **错误处理**：一致的错误格式
- **配置管理**：共享配置管理

## API 设计

### 核心 API

```python
class ANPNode:
    """支持服务器和客户端双模式的统一 ANP 节点。"""
    
    def __init__(
        self,
        name: str,
        description: str,
        did_document_path: str,
        private_key_path: str,
        agent_domain: str,
        host: str = "0.0.0.0",
        port: int = 8000,
        server_enabled: bool = True,
        client_enabled: bool = True,
        enable_auth_middleware: bool = True,
        auth_config: Optional[DidWbaVerifierConfig] = None,
        **kwargs
    ):
        """初始化 ANP 节点。"""
        pass
    
    # 服务器 API
    def interface(
        self,
        path: str,
        description: Optional[str] = None,
        humanAuthorization: bool = False
    ) -> Callable:
        """注册服务器接口的装饰器。"""
        pass
    
    def get_common_header(
        self,
        agent_description_path: str = "/ad.json",
        ad_url: Optional[str] = None
    ) -> Dict[str, Any]:
        """获取代理描述公共头部。"""
        pass
    
    # 客户端 API
    async def call_interface(
        self,
        target_did: str,
        method: str,
        params: Dict[str, Any],
        timeout: Optional[float] = 30.0
    ) -> Dict[str, Any]:
        """通过 DID 和方法名调用远程接口。"""
        pass
    
    async def discover_interface(
        self,
        target_did: str,
        method: Optional[str] = None
    ) -> Union[ANPInterface, Dict[str, ANPInterface]]:
        """发现并缓存远程接口。"""
        pass
    
    # 生命周期
    async def start(self) -> None:
        """
        以非阻塞模式启动节点服务器。
        
        此方法在后台启动服务器并立即返回。
        当您需要在服务器运行时执行其他操作时使用此方法。
        
        示例:
            async def main():
                node = ANPNode(...)
                await node.start()  # 非阻塞启动
                # 可以在这里做其他事情
                result = await node.call_interface(...)
                await node.stop()
        """
        pass
    
    async def stop(self) -> None:
        """
        优雅地停止节点服务器。
        
        停止服务器并等待正在进行的请求完成。
        """
        pass
    
    # 属性
    @property
    def did(self) -> str:
        """获取节点 DID。"""
        pass
    
    @property
    def interfaces(self) -> Dict[Callable, InterfaceProxy]:
        """获取已注册的服务器接口。"""
        pass
    
    @property
    def app(self) -> FastAPI:
        """获取 FastAPI 应用（用于高级用法）。"""
        pass
```

### 使用示例

#### 简单服务器节点

```python
from anp.node import ANPNode
import asyncio

# 初始化节点
node = ANPNode(
    name="简单代理",
    description="一个简单的 ANP 代理",
    did_document_path="./did.json",
    private_key_path="./private_key.pem",
    agent_domain="https://myagent.com",
    port=8000
)

# 注册服务器接口
@node.interface("/info/hello.json", description="问候")
def hello(name: str) -> dict:
    """向某人问好。"""
    return {"message": f"你好，{name}！"}

# 自定义 ad.json 路由
@node.app.get("/ad.json")
def get_agent_description():
    ad = node.get_common_header()
    ad["interfaces"] = [
        node.interfaces[hello].link_summary
    ]
    return ad

# 启动节点（最简设置）
if __name__ == "__main__":
    async def main():
        await node.start()
        try:
            await asyncio.Event().wait()  # 保持运行直到 Ctrl+C
        except KeyboardInterrupt:
            print("正在停止节点...")
            await node.stop()
    
    asyncio.run(main())
```

#### 双模式节点（服务器 + 客户端）

```python
from anp.node import ANPNode
from anp.fastanp import Context
import asyncio

# 初始化节点
node = ANPNode(
    name="编排代理",
    description="一个双模式 ANP 代理",
    did_document_path="./did.json",
    private_key_path="./private_key.pem",
    agent_domain="https://myagent.com",
    port=8000
)

# 注册调用其他节点的服务器接口
@node.interface("/info/aggregate.json", description="聚合多个节点的数据")
async def aggregate(query: str, ctx: Context = None) -> dict:
    """聚合多个节点的数据。"""
    results = []
    
    # 调用其他节点（客户端功能）
    try:
        result1 = await node.call_interface(
            target_did="did:wba:node1.com:agent:1",
            method="get_data",
            params={"query": query}
        )
        results.append(result1)
        
        result2 = await node.call_interface(
            target_did="did:wba:node2.com:agent:1",
            method="get_data",
            params={"query": query}
        )
        results.append(result2)
    except Exception as e:
        return {"error": str(e)}
    
    return {"aggregated": results, "count": len(results)}

# 自定义 ad.json 路由
@node.app.get("/ad.json")
def get_agent_description():
    ad = node.get_common_header()
    ad["interfaces"] = [
        node.interfaces[aggregate].link_summary
    ]
    return ad

# 启动节点并初始化（非阻塞式）
if __name__ == "__main__":
    async def main():
        # 启动服务器（非阻塞）
        await node.start()
        print("节点服务器已启动！")
        
        # 服务器运行时可以进行初始化
        try:
            # 发现其他节点
            interface = await node.discover_interface(
                target_did="did:wba:node1.com:agent:1",
                method="get_data"
            )
            print(f"发现的接口: {interface}")
        except Exception as e:
            print(f"发现失败: {e}")
        
        # 保持服务器运行直到停止
        try:
            await asyncio.Event().wait()  # 永久等待
        except KeyboardInterrupt:
            print("正在停止节点...")
            await node.stop()
    
    asyncio.run(main())
```

### 客户端使用示例

```python
# 在另一个脚本或异步上下文中
async def use_node_as_client():
    node = ANPNode(
        name="客户端代理",
        did_document_path="./client_did.json",
        private_key_path="./client_key.pem",
        agent_domain="https://client.com",
        server_enabled=False,  # 仅客户端模式
        client_enabled=True
    )
    
    # 发现远程接口
    interface = await node.discover_interface(
        target_did="did:wba:myagent.com:agent:1",
        method="search"
    )
    
    # 调用远程接口
    result = await interface.execute({
        "query": "测试",
        "limit": 10
    })
    
    print(result)
```

## 实施阶段

### 第一阶段：基础节点（MVP）

**目标**：具有基本功能的可工作双模式节点

**组件**：
- [ ] 节点配置和初始化
- [ ] 服务器组件包装器（FastANP 集成）
- [ ] 客户端组件包装器（ANPClient 集成）
- [ ] 共享身份管理
- [ ] 基本生命周期（启动/停止）
- [ ] 简单接口注册
- [ ] 基本远程接口调用

**时间线**：2-3 周

### 第二阶段：增强功能

**目标**：生产就绪的功能

**组件**：
- [ ] 接口发现和缓存
- [ ] 客户端连接池
- [ ] 请求路由（本地 vs 远程）
- [ ] 上下文传播
- [ ] 错误处理改进
- [ ] 超时和重试逻辑
- [ ] 健康检查

**时间线**：2-3 周

### 第三阶段：高级功能

**目标**：企业级能力

**组件**：
- [ ] 指标和监控
- [ ] 熔断器模式
- [ ] 负载均衡
- [ ] 服务网格集成
- [ ] 高级缓存策略
- [ ] 请求追踪
- [ ] 性能优化

**时间线**：3-4 周

## 设计决策

### 1. 组合优于继承

**决策**：使用组合来结合 FastANP 和 ANPClient

**理由**：
- 关注点分离清晰
- 更容易单独测试组件
- 配置更灵活
- 避免深层继承层次

### 2. 共享身份

**决策**：服务器和客户端模式使用相同的 DID

**理由**：
- 单一真实来源
- 一致的认证
- 配置更简单
- 更好的安全性（一个密钥对）

### 3. 可选组件

**决策**：允许禁用服务器或客户端模式

**理由**：
- 不同用例的灵活性
- 资源优化
- 更容易测试
- 支持专用节点

### 4. 异步优先设计

**决策**：所有 I/O 操作都是异步的

**理由**：
- 更好的性能
- 非阻塞操作
- 支持高并发
- 与 FastAPI 和 aiohttp 对齐

### 5. FastAPI 集成

**决策**：暴露 FastAPI 应用用于高级用法

**理由**：
- 用户可以添加自定义路由
- 支持中间件自定义
- 支持与其他 FastAPI 功能集成
- 保持灵活性

## 最佳实践

### 1. 错误处理

- **服务器错误**：返回适当的 JSON-RPC 错误响应
- **客户端错误**：优雅处理网络故障
- **使用一致的错误格式**：标准化错误代码和消息

### 2. 安全性

- **始终使用认证**：默认启用 DID WBA 认证
- **验证输入**：对接口参数使用 Pydantic 模型
- **速率限制**：为服务器端点实现速率限制
- **HTTPS**：在生产环境中使用 HTTPS

### 3. 性能

- **连接池**：重用 HTTP 连接
- **接口缓存**：缓存已发现的接口
- **异步操作**：全程使用 async/await
- **资源清理**：正确关闭连接和清理

### 4. 可观测性

- **结构化日志**：使用带节点身份的结构化日志
- **指标监控**：跟踪请求/响应指标
- **追踪**：支持分布式追踪
- **健康检查**：实现健康检查端点

### 5. 测试

- **单元测试**：独立测试组件
- **集成测试**：一起测试服务器和客户端
- **模拟外部节点**：使用模拟来测试客户端调用
- **测试两种模式**：确保服务器和客户端都正确工作

## 潜在挑战

### 1. 循环依赖

**问题**：节点 A 调用节点 B，节点 B 又调用节点 A

**解决方案**：
- 请求 ID 跟踪以检测循环
- 最大调用深度限制
- 超时机制
- 熔断器模式

### 2. 认证复杂性

**问题**：管理两种模式的认证

**解决方案**：
- 重用 DID WBA 认证
- 共享认证配置
- 清晰的文档
- 辅助工具

### 3. 状态管理

**问题**：服务器会话 vs 客户端请求状态

**解决方案**：
- 分离状态管理
- 清晰的边界
- 上下文传播
- 会话隔离

### 4. 测试复杂性

**问题**：测试服务器和客户端两种模式

**解决方案**：
- 模拟组件
- 集成测试框架
- 测试夹具
- 示例测试用例

## 与现有模式的比较

| 模式 | 示例 | ANP 节点 |
|------|------|----------|
| **客户端-服务器** | 传统 Web 应用 | 统一在一个类中 |
| **点对点** | BitTorrent, IPFS | 类似架构 |
| **微服务** | Kubernetes 服务 | 类似通信方式 |
| **代理网络** | ANP 愿景 | 完美匹配 |

## 实际用例

### 1. 代理编排

协调多个其他代理的代理：
- 接收请求（服务器模式）
- 调用其他代理来满足请求（客户端模式）
- 聚合结果

### 2. 服务网格

形成网络的多个节点：
- 每个节点提供服务
- 每个节点消费其他节点的服务
- 自动服务发现

### 3. 协商协议

协商协议的代理：
- 在协商期间充当服务器
- 充当客户端调用协商的接口
- 支持双向通信

### 4. 数据聚合

从多个源聚合数据的代理：
- 暴露聚合数据（服务器模式）
- 从多个源获取数据（客户端模式）
- 缓存和处理数据

## 迁移路径

### 对于现有 FastANP 用户

```python
# 之前（阻塞式）
app = FastAPI()
anp = FastANP(app=app, ...)
uvicorn.run(app, host="0.0.0.0", port=8000)  # 阻塞式

# 之后（非阻塞式）
node = ANPNode(...)
# node.app 是 FastAPI 应用
# node.interface() 工作方式相同

async def main():
    await node.start()  # 非阻塞
    # 可以做其他事情
    await asyncio.Event().wait()  # 保持运行

asyncio.run(main())
```

### 对于现有 ANPClient 用户

```python
# 之前
client = ANPClient(did_doc_path, key_path)
result = await client.fetch_url(...)

# 之后（仅客户端模式）
node = ANPNode(..., server_enabled=False, client_enabled=True)
result = await node.call_interface(
    target_did="did:wba:target.com:agent:1",
    method="method_name",
    params={...}
)
```

## 结论

统一的 ANP 节点设计提供：

✅ **简单性**：服务器和客户端的单一 API  
✅ **一致性**：共享身份和配置  
✅ **灵活性**：可选组件和高级自定义  
✅ **实际适用性**：匹配常见的分布式系统模式  
✅ **面向未来**：可扩展的架构以支持高级功能  

此设计在保持现有 ANP 组件简单性和强大功能的同时，实现了真正的点对点代理通信。

## 下一步

1. **审查和反馈**：收集对此设计的反馈
2. **原型**：构建第一阶段 MVP
3. **测试**：创建全面的测试套件
4. **文档**：编写用户指南和 API 文档
5. **示例**：创建示例实现
6. **迭代**：根据使用情况改进

---

**文档版本**：1.0  
**最后更新**：2025-01-XX  
**作者**：ANP 开发团队

