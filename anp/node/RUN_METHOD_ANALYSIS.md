# 阻塞式 `run()` 方法分析

## 问题概述

在设计文档中，`run()` 方法被设计为阻塞式（blocking），但标记为 `async def`，这存在概念上的矛盾。本文档分析阻塞式设计的利弊，并提供改进建议。

## 当前设计问题

### 设计文档中的定义

```python
async def run(self) -> None:
    """Run the node (blocking)."""
    pass
```

**问题**：
- `async def` 表示异步函数，通常是非阻塞的
- 注释说"阻塞式"，但异步函数本身不应该是阻塞的
- 这会导致概念混淆

### 实际使用场景

从代码库中看到两种模式：

1. **简单服务器模式**（阻塞式）：
```python
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)  # 阻塞式
```

2. **复杂节点模式**（需要非阻塞）：
```python
# start the node
alice_node.run()  # 如果是阻塞式，后面的代码无法执行

# connect to Bob, and negotiate the protocol
requester_session: RequesterSession = await alice_node.connect_to_did_with_negotiation(...)
```

## 阻塞式 `run()` 的好处

### ✅ 1. 简单直观

**优点**：
- 对于简单的服务器应用，阻塞式最直观
- 用户不需要理解异步编程
- 代码结构清晰：启动服务器，然后一直运行

**示例**：
```python
# 简单明了
if __name__ == "__main__":
    node = ANPNode(...)
    node.run()  # 启动后一直运行，直到 Ctrl+C
```

### ✅ 2. 符合传统服务器模式

**优点**：
- 与大多数 Web 框架一致（Flask, Django, uvicorn.run）
- 开发者熟悉这种模式
- 适合独立运行的服务器应用

**对比**：
```python
# Flask
app.run(host="0.0.0.0", port=5000)  # 阻塞式

# Django
python manage.py runserver  # 阻塞式

# FastAPI (uvicorn)
uvicorn.run(app, host="0.0.0.0", port=8000)  # 阻塞式
```

### ✅ 3. 适合独立进程

**优点**：
- 每个节点是独立进程
- 不需要在同一个事件循环中管理多个节点
- 进程隔离，更安全

**场景**：
```bash
# 启动多个独立节点
python node1.py  # 阻塞式运行
python node2.py  # 另一个进程，阻塞式运行
python node3.py  # 另一个进程，阻塞式运行
```

### ✅ 4. 资源管理简单

**优点**：
- 服务器运行期间，资源一直存在
- 不需要考虑生命周期管理
- 关闭时自动清理资源

## 阻塞式 `run()` 的坏处

### ❌ 1. 无法在同一进程中做其他事情

**问题**：
```python
# 如果 run() 是阻塞式的
node.run()  # 这里阻塞了

# 下面的代码永远无法执行
await node.call_interface(...)  # 无法执行
await node.discover_interface(...)  # 无法执行
```

**实际需求**：
- 节点启动后，还需要作为客户端调用其他节点
- 需要执行初始化逻辑
- 需要处理后台任务

### ❌ 2. 测试困难

**问题**：
```python
# 测试中无法同时启动多个节点
async def test_two_nodes():
    node1 = ANPNode(...)
    node2 = ANPNode(...)
    
    node1.run()  # 阻塞，无法继续
    node2.run()  # 永远无法执行
    
    # 无法测试节点间的交互
    result = await node1.call_interface(node2.did, ...)
```

**解决方案**：需要多进程或线程，增加测试复杂度

### ❌ 3. 无法集成到异步应用

**问题**：
```python
# 在异步应用中使用
async def main():
    # 启动多个服务
    node1 = ANPNode(...)
    node2 = ANPNode(...)
    
    # 无法同时运行
    await asyncio.gather(
        node1.run(),  # 如果是阻塞式，无法 await
        node2.run(),
        other_async_task()
    )
```

### ❌ 4. 无法优雅关闭

**问题**：
```python
# 阻塞式难以实现优雅关闭
node.run()  # 阻塞中，无法响应关闭信号

# 需要外部信号（SIGTERM, SIGINT）才能关闭
# 无法在代码中控制关闭时机
```

### ❌ 5. 与异步设计理念冲突

**问题**：
- ANP Node 设计为异步优先
- 客户端组件使用 `async/await`
- 服务器组件基于 FastAPI（异步框架）
- 阻塞式 `run()` 与整体异步设计不一致

## 改进方案

### 方案 1：分离阻塞式和非阻塞式方法（推荐）

**设计**：
```python
class ANPNode:
    # 阻塞式方法（同步）
    def run(self) -> None:
        """Run the node in blocking mode (for simple use cases)."""
        import uvicorn
        uvicorn.run(self.app, host=self.host, port=self.port)
    
    # 非阻塞式方法（异步）
    async def start(self) -> None:
        """Start the node server (non-blocking)."""
        from uvicorn import Config, Server
        config = Config(self.app, host=self.host, port=self.port)
        server = Server(config)
        await server.serve()
    
    async def stop(self) -> None:
        """Stop the node server."""
        if self._server:
            self._server.should_exit = True
```

**使用场景**：

1. **简单服务器**（阻塞式）：
```python
if __name__ == "__main__":
    node = ANPNode(...)
    node.run()  # 阻塞式，简单直接
```

2. **复杂节点**（非阻塞式）：
```python
async def main():
    node = ANPNode(...)
    
    # 启动服务器（非阻塞）
    server_task = asyncio.create_task(node.start())
    
    # 等待服务器就绪
    await asyncio.sleep(1)
    
    # 作为客户端调用其他节点
    result = await node.call_interface(
        target_did="did:wba:other.com:node:1",
        method="get_data",
        params={"id": 123}
    )
    
    # 可以同时做其他事情
    await other_async_task()
    
    # 优雅关闭
    await node.stop()
    await server_task

asyncio.run(main())
```

### 方案 2：使用上下文管理器

**设计**：
```python
class ANPNode:
    async def __aenter__(self):
        """Async context manager entry."""
        await self.start()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        await self.stop()
    
    async def start(self) -> None:
        """Start the node server."""
        # 非阻塞启动
        pass
    
    async def stop(self) -> None:
        """Stop the node server."""
        # 优雅关闭
        pass
```

**使用**：
```python
async def main():
    async with ANPNode(...) as node:
        # 节点已启动，可以同时使用服务器和客户端功能
        result = await node.call_interface(...)
        # 自动清理
```

### 方案 3：提供两种模式

**设计**：
```python
class ANPNode:
    def __init__(
        self,
        ...,
        blocking_mode: bool = False  # 新增参数
    ):
        self.blocking_mode = blocking_mode
        # ...
    
    def run(self) -> None:
        """Run the node.
        
        If blocking_mode=True, runs in blocking mode.
        If blocking_mode=False, starts server in background.
        """
        if self.blocking_mode:
            # 阻塞式
            import uvicorn
            uvicorn.run(self.app, host=self.host, port=self.port)
        else:
            # 非阻塞式
            asyncio.create_task(self._start_server())
    
    async def _start_server(self) -> None:
        """Internal method to start server in background."""
        from uvicorn import Config, Server
        config = Config(self.app, host=self.host, port=self.port)
        server = Server(config)
        await server.serve()
```

## 推荐方案：方案 1（分离方法）

### 最终 API 设计

```python
class ANPNode:
    """Unified ANP node supporting both server and client modes."""
    
    # 阻塞式方法（同步，简单场景）
    def run(self) -> None:
        """
        Run the node in blocking mode.
        
        This method blocks until the server is stopped (Ctrl+C).
        Suitable for simple server-only use cases.
        
        Example:
            if __name__ == "__main__":
                node = ANPNode(...)
                node.run()  # Blocks here
        """
        import uvicorn
        uvicorn.run(
            self.app,
            host=self.host,
            port=self.port,
            log_level="info"
        )
    
    # 非阻塞式方法（异步，复杂场景）
    async def start(self) -> None:
        """
        Start the node server in non-blocking mode.
        
        This method starts the server in the background and returns immediately.
        Use this when you need to do other things while the server is running.
        
        Example:
            async def main():
                node = ANPNode(...)
                await node.start()  # Non-blocking
                # Can do other things here
                result = await node.call_interface(...)
                await node.stop()
        """
        from uvicorn import Config, Server
        
        config = Config(
            self.app,
            host=self.host,
            port=self.port,
            log_level="info"
        )
        self._server = Server(config)
        
        # Start server in background
        self._server_task = asyncio.create_task(self._server.serve())
        
        # Wait for server to be ready
        while not self._server.started:
            await asyncio.sleep(0.1)
        
        logger.info(f"Node server started on {self.host}:{self.port}")
    
    async def stop(self) -> None:
        """
        Stop the node server gracefully.
        
        Stops the server and waits for ongoing requests to complete.
        """
        if hasattr(self, '_server') and self._server:
            self._server.should_exit = True
            if hasattr(self, '_server_task'):
                await self._server_task
            logger.info("Node server stopped")
    
    async def run_async(self) -> None:
        """
        Run the node in async mode (convenience method).
        
        Starts the server and runs until stopped.
        Equivalent to: await start() then wait forever.
        
        Example:
            async def main():
                node = ANPNode(...)
                await node.run_async()  # Runs until stopped
        """
        await self.start()
        try:
            # Keep running until stopped
            while True:
                await asyncio.sleep(1)
        except KeyboardInterrupt:
            await self.stop()
```

### 使用示例对比

#### 场景 1：简单服务器（阻塞式）

```python
# 简单直接，适合独立运行的服务器
if __name__ == "__main__":
    node = ANPNode(
        name="Simple Server",
        did_document_path="./did.json",
        private_key_path="./key.pem",
        agent_domain="https://example.com"
    )
    
    @node.interface("/info/hello.json")
    def hello(name: str) -> dict:
        return {"message": f"Hello, {name}!"}
    
    node.run()  # 阻塞式，简单明了
```

#### 场景 2：双模式节点（非阻塞式）

```python
# 需要同时作为服务器和客户端
async def main():
    node = ANPNode(
        name="Dual Mode Node",
        did_document_path="./did.json",
        private_key_path="./key.pem",
        agent_domain="https://example.com"
    )
    
    @node.interface("/info/process.json")
    async def process(data: dict, ctx: Context = None) -> dict:
        # 服务器接口中调用其他节点
        result = await node.call_interface(
            target_did="did:wba:other.com:node:1",
            method="analyze",
            params={"data": data}
        )
        return {"processed": result}
    
    # 非阻塞启动
    await node.start()
    
    # 可以同时作为客户端
    other_result = await node.call_interface(
        target_did="did:wba:another.com:node:1",
        method="get_info",
        params={}
    )
    
    # 可以执行其他异步任务
    await background_task()
    
    # 优雅关闭
    await node.stop()

asyncio.run(main())
```

#### 场景 3：测试场景（非阻塞式）

```python
# 测试中需要同时运行多个节点
async def test_node_interaction():
    node1 = ANPNode(..., port=8001)
    node2 = ANPNode(..., port=8002)
    
    # 同时启动
    await asyncio.gather(
        node1.start(),
        node2.start()
    )
    
    try:
        # 测试节点间交互
        result = await node1.call_interface(
            target_did=node2.did,
            method="test_method",
            params={}
        )
        assert result["success"]
    finally:
        # 清理
        await asyncio.gather(
            node1.stop(),
            node2.stop()
        )
```

## 总结

### 阻塞式 `run()` 的适用场景

✅ **适合**：
- 简单的独立服务器
- 不需要在运行时做其他事情
- 传统服务器应用模式
- 快速原型和演示

### 非阻塞式 `start()` 的适用场景

✅ **适合**：
- 双模式节点（同时是服务器和客户端）
- 需要执行初始化逻辑
- 测试场景（多个节点）
- 集成到异步应用
- 需要优雅关闭
- 后台任务处理

### 推荐设计

**提供两种方法**：
1. `run()` - 阻塞式，简单场景
2. `start()` / `stop()` - 非阻塞式，复杂场景

这样既保持了简单性，又提供了灵活性。

---

**文档版本**：1.0  
**最后更新**：2025-01-XX

