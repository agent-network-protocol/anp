"""OpenANP SDK - 纯函数工具

这个模块提供纯函数，用于生成 ANP 协议文档。
所有函数都是纯函数：同样的输入总是产生同样的输出，
没有任何副作用。

设计原则：
- 纯函数：没有副作用，可预测
- 无状态：不依赖外部状态
- 可组合：可以组合使用
- 类型安全：完整的类型提示
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Literal

from .types import AgentConfig, RPCMethodInfo

if TYPE_CHECKING:
    from fastapi import Request

__all__ = [
    "generate_ad_document",
    "generate_rpc_interface",
    "resolve_base_url",
]


# =============================================================================
# 核心文档生成函数
# =============================================================================


def generate_ad_document(
    config: AgentConfig,
    base_url: str,
    interfaces: list[dict[str, Any]] | None = None,
    inline_methods: list[RPCMethodInfo] | None = None,
) -> dict[str, Any]:
    """生成 Agent Description (ad.json) 文档。

    新版格式采用产品型描述而非 JSON-LD，保留 ANP 协议信息和安全声明，
    便于目录/客户端直接消费。

    Args:
        config: Agent 配置
        base_url: 基础 URL（协议 + 主机名）
        interfaces: 接口引用列表，可选
        inline_methods: 如果提供，将根据这些方法生成 OpenRPC 文档并内联到 ad.json 中

    Returns:
        ad.json 文档字典

    Example:
        config = AgentConfig(name="Hotel", did="did:wba:example.com:hotel")
        # 方式 1: 引用外部接口
        doc = generate_ad_document(config, "https://api.example.com")

        # 方式 2: 内联接口
        methods = [...]
        doc = generate_ad_document(config, "https://api.example.com", inline_methods=methods)
    """

    # 构建完整路径
    full_path = f"{config.prefix}/ad.json" if config.prefix else "/ad.json"

    # 构建接口列表
    interface_refs = interfaces or []

    # 处理 URL 配置中的接口引用
    if config.url_config and "interface_url" in config.url_config:
        interface_refs.append(
            {
                "type": "StructuredInterface",
                "protocol": "openrpc",
                "url": config.url_config["interface_url"],
                "description": f"{config.name} JSON-RPC interface",
            }
        )

    # 处理内联 RPC 方法
    if inline_methods:
        # 生成 OpenRPC 文档
        openrpc_doc = generate_rpc_interface(config, base_url, inline_methods)
        interface_refs.append(
            {
                "type": "InlineOpenRPC",
                "protocol": "openrpc",
                "definition": openrpc_doc,
                "description": f"{config.name} Inline JSON-RPC interface",
            }
        )

    # 生成产品型 Agent Description（非 JSON-LD）
    doc: dict[str, Any] = {
        "protocolType": "ANP",
        "protocolVersion": "1.0.0",
        "type": "Product",
        "url": f"{base_url}{full_path}",
        "identifier": config.did,
        "name": config.name,
        "description": config.description or config.name,
        "security": {
            "didwba": {"scheme": "didwba", "in": "header", "name": "Authorization"}
        },
        "brand": {"type": "Brand", "name": config.name},
        "category": "Agent Service",
        "sku": config.did,
        # UTC timestamp in ISO 8601 second precision
        "created": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }

    if interface_refs:
        doc["interfaces"] = interface_refs

    return doc


def _convert_schema_to_openrpc_params(schema: dict[str, Any]) -> list[dict[str, Any]]:
    """Convert JSON Schema to OpenRPC params array (ContentDescriptor format).

    Trust upstream: schema must have properties, no fallback.
    """
    properties = schema["properties"]
    required_fields = set(schema.get("required", []))

    return [
        {
            "name": param_name,
            "schema": param_schema,
            "required": True,
        }
        if param_name in required_fields
        else {
            "name": param_name,
            "schema": param_schema,
        }
        for param_name, param_schema in properties.items()
    ]


def _convert_schema_to_openrpc_result(schema: dict[str, Any]) -> dict[str, Any]:
    """Convert JSON Schema to OpenRPC result ContentDescriptor."""
    return {"name": "result", "schema": schema}


def generate_rpc_interface(
    config: AgentConfig,
    base_url: str,
    methods: list[RPCMethodInfo],
    protocol_version: Literal["1.0", "2.0"] = "1.0",
) -> dict[str, Any]:
    """生成 RPC 接口文档 (interface.json)。

    生成符合 OpenRPC 规范的接口文档，描述所有可用的 RPC 方法。
    如果方法指定了 protocol 字段（如 "AP2/ANP"），会在方法中添加 x-protocol 扩展字段。

    Args:
        config: Agent 配置
        base_url: 基础 URL
        methods: RPC 方法信息列表
        protocol_version: 协议版本，默认 "1.0"

    Returns:
        OpenRPC 格式的接口文档

    Example:
        methods = [
            RPCMethodInfo(
                name="search",
                description="Search for hotels",
                params_schema={...},
                result_schema={...}
            ),
            RPCMethodInfo(
                name="cart_mandate",
                description="Create cart mandate",
                protocol="AP2/ANP",  # AP2 方法
                params_schema={...},
                result_schema={...}
            )
        ]
        doc = generate_rpc_interface(config, "https://api.example.com", methods)
        # 返回符合 OpenRPC 的接口文档，AP2 方法会包含 x-protocol 字段
    """
    # Convert to OpenRPC methods (trust upstream data)
    rpc_methods = []
    for m in methods:
        method = {
            "name": m.name,
            "description": m.description,
            "params": _convert_schema_to_openrpc_params(m.params_schema),
            "result": _convert_schema_to_openrpc_result(m.result_schema),
        }
        if m.protocol:
            method["x-protocol"] = m.protocol
        rpc_methods.append(method)

    # 构建 RPC URL
    rpc_url = f"{base_url}{config.prefix}/rpc" if config.prefix else f"{base_url}/rpc"

    # 生成接口文档
    doc = {
        "openrpc": "1.3.2",
        "info": {
            "title": f"{config.name} API",
            "version": "1.0.0",
            "description": config.description or config.name,
        },
        "methods": rpc_methods,
        "servers": [
            {
                "name": f"{config.name} Server",
                "url": rpc_url,
            }
        ],
        "securityDefinitions": {
            "didwba_sc": {"scheme": "didwba", "in": "header", "name": "Authorization"}
        },
        "security": "didwba_sc",
    }

    return doc


# =============================================================================
# URL 工具函数
# =============================================================================


def resolve_base_url(request: Request) -> str:
    """从 FastAPI Request 解析基础 URL。

    从请求对象中提取协议、主机名和端口，
    构建成标准的基础 URL。

    Note:
        在 macOS 上，0.0.0.0 会导致 CORS 问题，
        因此自动将其替换为 127.0.0.1
        在 Windows 和 Linux 上，0.0.0.0 也会被替换为 127.0.0.1 以保持一致性

    Args:
        request: FastAPI Request 对象

    Returns:
        基础 URL 字符串，格式：https://example.com

    Example:
        request = Request(...)
        base_url = resolve_base_url(request)
        # 返回: "https://api.example.com"
    """
    import platform

    # 从请求中提取基础 URL
    base_url = str(request.base_url).rstrip("/")

    # 检测操作系统
    system = platform.system().lower()

    # 在 macOS (darwin) 上，0.0.0.0 会导致 CORS 问题
    # 在所有平台上统一将 0.0.0.0 替换为 127.0.0.1 以保持一致性和避免潜在问题
    # 服务器仍然监听 0.0.0.0（所有接口），但生成的 URL 使用 127.0.0.1
    if "0.0.0.0" in base_url:
        if system == "darwin":
            # macOS: 必须替换以避免 CORS 问题
            base_url = base_url.replace("://0.0.0.0:", "://127.0.0.1:")
            base_url = base_url.replace("://0.0.0.0/", "://127.0.0.1/")
            if base_url.endswith("://0.0.0.0"):
                base_url = base_url.replace("://0.0.0.0", "://127.0.0.1")
        elif system in ("linux", "windows"):
            # Linux/Windows: 也替换以保持一致性
            base_url = base_url.replace("://0.0.0.0:", "://127.0.0.1:")
            base_url = base_url.replace("://0.0.0.0/", "://127.0.0.1/")
            if base_url.endswith("://0.0.0.0"):
                base_url = base_url.replace("://0.0.0.0", "://127.0.0.1")

    return base_url


# =============================================================================
# 验证工具函数
# =============================================================================


def validate_rpc_request(request_body: dict[str, Any]) -> tuple[str, dict, Any]:
    """验证并解析 RPC 请求。

    Args:
        request_body: 请求体字典

    Returns:
        (method, params, request_id) 元组

    Raises:
        ValueError: 当请求格式不正确时
    """
    # 检查 JSON-RPC 2.0 格式
    if "jsonrpc" not in request_body:
        raise ValueError("Missing 'jsonrpc' field")

    if request_body["jsonrpc"] != "2.0":
        raise ValueError("Only JSON-RPC 2.0 is supported")

    if "method" not in request_body:
        raise ValueError("Missing 'method' field")

    method = request_body["method"]
    params = request_body.get("params", {})
    req_id = request_body.get("id")

    return method, params, req_id


def create_rpc_response(
    result: Any,
    request_id: Any = None,
) -> dict[str, Any]:
    """创建 RPC 响应。

    Args:
        result: 响应结果
        request_id: 请求 ID

    Returns:
        符合 JSON-RPC 2.0 格式的响应字典

    Example:
        response = create_rpc_response({"data": "value"}, 1)
        # 返回: {"jsonrpc": "2.0", "result": {"data": "value"}, "id": 1}
    """
    response = {
        "jsonrpc": "2.0",
        "result": result,
    }

    if request_id is not None:
        response["id"] = request_id

    return response


def create_rpc_error(
    code: int,
    message: str,
    request_id: Any = None,
    data: Any = None,
) -> dict[str, Any]:
    """创建 RPC 错误响应。

    Args:
        code: 错误代码（JSON-RPC 标准错误码）
        message: 错误消息
        request_id: 请求 ID
        data: 额外错误数据

    Returns:
        符合 JSON-RPC 2.0 格式的错误响应字典

    Example:
        response = create_rpc_error(-32601, "Method not found", 1)
        # 返回: {"jsonrpc": "2.0", "error": {"code": -32601, "message": "Method not found"}, "id": 1}
    """
    error = {
        "code": code,
        "message": message,
    }

    if data is not None:
        error["data"] = data

    response = {
        "jsonrpc": "2.0",
        "error": error,
    }

    if request_id is not None:
        response["id"] = request_id

    return response


# =============================================================================
# 常量定义
# =============================================================================


# JSON-RPC 错误码（标准定义）
class RPCErrorCodes:
    """JSON-RPC 标准错误码。"""

    PARSE_ERROR = -32700
    INVALID_REQUEST = -32600
    METHOD_NOT_FOUND = -32601
    INVALID_PARAMS = -32602
    INTERNAL_ERROR = -32603
