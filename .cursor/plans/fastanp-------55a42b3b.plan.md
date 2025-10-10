<!-- 55a42b3b-3d4c-4a66-bd23-5a26951c2063 22add13b-ecca-405e-b8fd-86b5e1c1aae7 -->
# FastANP 插件化重构方案

## 核心设计变更

**从**: FastANP 作为框架，自动管理所有路由和生成

**到**: FastAPI 作为主框架，FastANP 作为插件辅助工具

## 关键接口设计

### 1. 初始化方式变更

**旧设计**:

```python
app = FastANP(name="...", description="...", ...)
```

**新设计**:

```python
app = FastAPI()
anp = FastANP(
    app=app,  # 传入 FastAPI 实例
    name="...",
    description="...",
    base_url="...",
    did="...",
    did_document_path="...",
    private_key_path="...",
    public_key_path="...",
    owner={...},
    jsonrpc_server_url="...",  # JSON-RPC 端点路径，默认 "/rpc"
    jsonrpc_server_name="...",
    jsonrpc_server_description="...",
    external_nonce_validator=None,
    require_auth=False,
    enable_auth_middleware=True
)
```

### 2. 路由完全由用户控制

用户手动定义 ad.json 路由：

```python
@app.get("/{agent_id}/ad.json")
def get_agent_description(agent_id: str):
    # 获取公共头部
    ad = anp.get_common_header()
    
    # 添加 Information（用户自定义）
    ad["Infomations"] = [
        {
            "type": "Product",
            "description": "...",
            "url": f"{anp.base_url}/luxury-rooms.json"
        }
    ]
    
    # 添加 Interface（通过 FastANP 辅助）
    ad["interfaces"] = [
        anp.interfaces[search_rooms].link_summary,  # 链接模式
        # 或
        anp.interfaces[get_rooms].content  # 嵌入模式
    ]
    
    return ad
```

### 3. Interface 装饰器和访问

```python
@anp.interface("/info/search_rooms.json")
def search_rooms(query: str) -> dict:
    """接口函数"""
    pass

# 访问接口元数据
anp.interfaces[search_rooms].link_summary  # 返回 link 形式的接口摘要
anp.interfaces[search_rooms].content       # 返回完整 OpenRPC 内容
anp.interfaces[search_rooms].openrpc_doc   # 返回 OpenRPC 文档对象
```

### 4. Context 自动注入

```python
@anp.interface("/info/get_rooms.json")
def get_rooms(query: str, ctx: Context) -> dict:
    """
    Args:
        query: 查询参数
        ctx: 自动注入的上下文（基于 DID + Access Token 识别 session）
    """
    return {"session": ctx.session.id, "did": ctx.did}
```

### 5. 中间件支持

```python
# 可选添加鉴权中间件
app.add_middleware(anp.auth_middleware, minimum_size=500)
```

## 实现计划

### 阶段 1: 重构 FastANP 主类 (fastanp.py)

**变更点**:

1. `__init__` 接受 `app: FastAPI` 参数
2. 移除 `self.app = FastAPI()` 创建逻辑
3. 移除自动注册 `/ad.json` 端点
4. 添加 `jsonrpc_server_url` 参数（默认 `/rpc`）
5. 添加 `enable_auth_middleware` 参数
6. 在初始化时自动注册 JSON-RPC 端点到 FastAPI
7. 添加 `get_common_header()` 方法返回 ad.json 公共头部
8. 添加 `interfaces` 属性作为字典，key 为函数对象
9. 移除 `finalize()` 自动路由注册逻辑
10. 移除 `run()` 方法（由 FastAPI 直接运行）
11. 保留 `auth_middleware` 属性供用户使用

### 阶段 2: 重构 Interface 管理器 (interface_manager.py)

**变更点**:

1. `register_function()` 接受 `path` 参数（OpenRPC 文档路径）
2. 自动注册 `GET {path}` 路由返回该接口的 OpenRPC 文档
3. 创建 `InterfaceProxy` 类，提供 `.link_summary`, `.content`, `.openrpc_doc` 属性
4. `InterfaceManager.get_interface()` 返回 `InterfaceProxy` 对象
5. 自动注册 JSON-RPC 统一端点（`/rpc`）
6. 实现 JSON-RPC 请求分发到对应函数
7. 支持函数签名检测，自动注入 `Context` 参数
8. 检查函数名全局唯一性，重复时抛出异常

### 阶段 3: 实现 Context 注入机制

**新增文件**: `anp/fastanp/context.py`

**实现**:

1. 定义 `Context` 类，包含：

   - `session: Session` - 会话对象（基于 DID + Access Token）
   - `did: str` - 请求方 DID
   - `request: Request` - FastAPI Request 对象
   - `auth_result: dict` - 认证结果

2. 定义 `Session` 类，包含：

   - `id: str` - Session ID（基于 DID + Token 哈希生成）
   - `did: str` - DID
   - `created_at: datetime` - 创建时间
   - `data: dict` - Session 数据存储

3. 实现 `SessionManager` 管理 session 生命周期
4. 在 JSON-RPC 处理器中检测函数签名
5. 如果参数包含 `ctx: Context`，自动注入

### 阶段 4: 重构 AD Generator (ad_generator.py)

**变更点**:

1. 简化为仅生成公共头部
2. `generate_common_header()` 方法返回基础字段：

   - `protocolType`, `protocolVersion`, `type`, `url`
   - `name`, `did`, `description`, `created`
   - `securityDefinitions`, `security`（如果需要）
   - `owner`（如果有）

3. 移除 `informations` 和 `interfaces` 自动合并逻辑

### 阶段 5: 简化 Information 管理器 (information.py)

**变更点**:

1. 移除自动路由注册逻辑
2. 保留 `InformationItem` 类作为数据模型
3. 或者完全移除（因为用户自己管理）

### 阶段 6: 实现 InterfaceProxy

**新增**: `InterfaceProxy` 类提供接口元数据访问

```python
class InterfaceProxy:
    def __init__(self, func, openrpc_doc, path, base_url):
        self.func = func
        self.path = path
        self.base_url = base_url
        self._openrpc_doc = openrpc_doc
    
    @property
    def link_summary(self) -> dict:
        """返回链接形式的接口摘要"""
        return {
            "type": "StructuredInterface",
            "protocol": "openrpc",
            "description": "...",
            "url": f"{self.base_url}{self.path}"
        }
    
    @property
    def content(self) -> dict:
        """返回嵌入式完整内容"""
        return {
            "type": "StructuredInterface",
            "protocol": "openrpc",
            "description": "...",
            "content": self._openrpc_doc
        }
    
    @property
    def openrpc_doc(self) -> dict:
        """返回 OpenRPC 文档"""
        return self._openrpc_doc
```

### 阶段 7: 中间件重构 (middleware.py)

**变更点**:

1. 将 `AuthManager` 转换为 FastAPI 中间件类
2. 提供 `anp.auth_middleware` 供用户添加
3. 支持可选参数（如 `minimum_size`）

### 阶段 8: 更新示例和文档

**变更点**:

1. 重写 `simple_agent.py` 使用新接口
2. 更新 `hotel_booking_agent.py` 确保可运行
3. 更新 `README.md` 文档
4. 更新 `QUICKSTART.md` 快速开始
5. 更新 `IMPLEMENTATION.md` 实现说明

### 阶段 9: 更新单元测试

**变更点**:

1. 重写 `test_fastanp.py` 适配新接口
2. 添加 Context 注入测试
3. 添加 Session 管理测试
4. 添加 InterfaceProxy 测试
5. 添加 JSON-RPC 分发测试

## 关键实现细节

### 函数名全局唯一性检查

```python
# 在 InterfaceManager 中
self.registered_names = set()

def register_function(self, func, path, ...):
    func_name = func.__name__
    if func_name in self.registered_names:
        raise ValueError(f"Function name '{func_name}' already registered")
    self.registered_names.add(func_name)
```

### JSON-RPC 自动端点注册

在 `FastANP.__init__()` 中：

```python
# 自动注册 JSON-RPC 端点
self.interface_manager.register_jsonrpc_endpoint(
    app=self.app,
    rpc_path=jsonrpc_server_url,
    auth_manager=self.auth_manager if require_auth else None
)
```

### OpenRPC 文档路由自动注册

在 `@anp.interface(path)` 装饰器中：

```python
def interface(self, path: str):
    def decorator(func):
        # 注册函数
        self.interface_manager.register_function(func, path)
        
        # 自动注册 GET path 路由返回 OpenRPC 文档
        @self.app.get(path)
        async def get_openrpc():
            return self.interfaces[func].openrpc_doc
        
        return func
    return decorator
```

### Context 自动注入实现

在 JSON-RPC 处理器中：

```python
sig = inspect.signature(func)
params_to_inject = {}

for param_name, param in sig.parameters.items():
    if param.annotation == Context:
        # 构造 Context 对象
        context = Context(
            session=session_manager.get_or_create(did, token),
            did=auth_result['did'],
            request=request,
            auth_result=auth_result
        )
        params_to_inject[param_name] = context

# 合并用户传入的参数
final_params = {**json_rpc_params, **params_to_inject}
result = func(**final_params)
```

## 兼容性考虑

- 保留旧 API 的废弃警告（可选）
- 提供迁移指南文档
- 示例中同时展示新旧用法对比

## 测试策略

1. 单元测试覆盖所有新功能
2. 集成测试验证 JSON-RPC 端到端流程
3. 测试 Context 注入在各种场景下的正确性
4. 测试函数名重复检测
5. 测试中间件集成

### To-dos

- [ ] 重构 FastANP 主类：接受 FastAPI 实例，添加 get_common_header() 方法，添加 interfaces 字典属性，移除自动路由注册
- [ ] 实现 Context 注入机制：创建 Context、Session、SessionManager 类
- [ ] 重构 Interface 管理器：支持 path 参数，自动注册 OpenRPC 文档路由，实现 InterfaceProxy，添加函数名唯一性检查
- [ ] 实现 JSON-RPC 自动端点和请求分发：注册统一 /rpc 端点，支持 Context 自动注入
- [ ] 简化 AD Generator：仅生成公共头部，移除自动合并逻辑
- [ ] 重构中间件：转换为 FastAPI 中间件类，提供 auth_middleware 属性
- [ ] 更新示例代码：重写 simple_agent.py 和 hotel_booking_agent.py
- [ ] 更新文档：README.md, QUICKSTART.md, IMPLEMENTATION.md
- [ ] 更新单元测试：适配新接口，添加 Context、Session、InterfaceProxy 测试