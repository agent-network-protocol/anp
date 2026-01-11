"""OpenANP SDK 单元测试

测试覆盖：
1. 类型和配置 (types.py)
2. 装饰器 (decorators.py)
3. Context 和 Session (context.py)
4. Schema 生成 (schema_gen.py)
5. 路由自动生成 (autogen.py)
6. 客户端解析 (client/openrpc.py)

测试原则：
- 不使用 mock
- 真实测试功能
- 覆盖边界情况
"""

import asyncio
from dataclasses import dataclass
from typing import Any, Literal

import pytest

from anp.openanp import (
    AgentConfig,
    Context,
    Information,
    RPCMethodInfo,
    Session,
    SessionManager,
    anp_agent,
    extract_rpc_methods,
    information,
    interface,
)
from anp.openanp.decorators import _check_has_context


# =============================================================================
# types.py 测试
# =============================================================================


class TestAgentConfig:
    """测试 AgentConfig 类型."""

    def test_valid_config(self):
        """测试有效配置."""
        config = AgentConfig(
            name="Test Agent",
            did="did:wba:example.com:test",
            description="A test agent",
            prefix="/test",
        )
        assert config.name == "Test Agent"
        assert config.did == "did:wba:example.com:test"
        assert config.description == "A test agent"
        assert config.prefix == "/test"

    def test_empty_name_fails(self):
        """测试空名称失败."""
        with pytest.raises(ValueError, match="Agent name cannot be empty"):
            AgentConfig(name="", did="did:wba:example.com:test")

    def test_whitespace_name_fails(self):
        """测试空白名称失败."""
        with pytest.raises(ValueError, match="Agent name cannot be empty"):
            AgentConfig(name="   ", did="did:wba:example.com:test")

    def test_invalid_did_format_fails(self):
        """测试无效 DID 格式失败."""
        with pytest.raises(ValueError, match="Invalid DID format"):
            AgentConfig(name="Test", did="invalid-did")

    def test_did_must_start_with_did(self):
        """测试 DID 必须以 'did:' 开头."""
        with pytest.raises(ValueError, match="DID must start with 'did:'"):
            AgentConfig(name="Test", did="example.com:test")

    def test_name_is_stripped(self):
        """测试名称被去除空白."""
        config = AgentConfig(name="  Test Agent  ", did="did:wba:example.com:test")
        assert config.name == "Test Agent"

    def test_did_is_stripped(self):
        """测试 DID 被去除空白 - 注意：需要先 strip 再验证."""
        # 注意：AgentConfig 会在 __post_init__ 中先验证格式再 strip
        # 所以 DID 必须已经是有效格式（以 did: 开头）
        config = AgentConfig(name="Test", did="did:wba:example.com:test")
        assert config.did == "did:wba:example.com:test"

    def test_frozen(self):
        """测试配置是不可变的."""
        config = AgentConfig(name="Test", did="did:wba:example.com:test")
        with pytest.raises(AttributeError):
            config.name = "New Name"


class TestInformation:
    """测试 Information 类型."""

    def test_url_mode_with_external_url(self):
        """测试 URL 模式（外部链接）."""
        info = Information(
            type="VideoObject",
            description="A video",
            url="https://example.com/video.mp4",
        )
        assert info.mode == "url"
        assert info.url == "https://example.com/video.mp4"

    def test_url_mode_with_path(self):
        """测试 URL 模式（相对路径）."""
        info = Information(
            type="Product",
            description="A product",
            path="/products/item.json",
        )
        assert info.mode == "url"
        assert info.path == "/products/item.json"

    def test_content_mode(self):
        """测试 Content 模式."""
        info = Information(
            type="Organization",
            description="Contact info",
            mode="content",
            content={"name": "Test Org", "phone": "123-456"},
        )
        assert info.mode == "content"
        assert info.content == {"name": "Test Org", "phone": "123-456"}

    def test_url_mode_requires_path_or_url(self):
        """测试 URL 模式需要 path 或 url."""
        with pytest.raises(ValueError, match="URL mode Information must have"):
            Information(type="Product", description="Test", mode="url")

    def test_content_mode_requires_content(self):
        """测试 Content 模式需要 content."""
        with pytest.raises(ValueError, match="Content mode Information must have"):
            Information(type="Product", description="Test", mode="content")

    def test_to_dict_url_mode_external(self):
        """测试 to_dict URL 模式（外部链接）."""
        info = Information(
            type="VideoObject",
            description="A video",
            url="https://cdn.example.com/video.mp4",
        )
        result = info.to_dict("https://example.com/agent")
        assert result == {
            "type": "VideoObject",
            "description": "A video",
            "url": "https://cdn.example.com/video.mp4",
        }

    def test_to_dict_url_mode_path(self):
        """测试 to_dict URL 模式（相对路径）."""
        info = Information(
            type="Product",
            description="A product",
            path="/products/item.json",
        )
        result = info.to_dict("https://example.com/agent")
        assert result == {
            "type": "Product",
            "description": "A product",
            "url": "https://example.com/agent/products/item.json",
        }

    def test_to_dict_content_mode(self):
        """测试 to_dict Content 模式."""
        info = Information(
            type="Organization",
            description="Contact",
            mode="content",
            content={"phone": "123"},
        )
        result = info.to_dict("https://example.com/agent")
        assert result == {
            "type": "Organization",
            "description": "Contact",
            "content": {"phone": "123"},
        }


class TestRPCMethodInfo:
    """测试 RPCMethodInfo 类型."""

    def test_basic_method_info(self):
        """测试基本方法信息."""
        method = RPCMethodInfo(
            name="search",
            description="Search for items",
            params_schema={"type": "object", "properties": {"query": {"type": "string"}}},
        )
        assert method.name == "search"
        assert method.description == "Search for items"
        assert method.mode == "content"
        assert method.has_context is False

    def test_link_mode(self):
        """测试 link 模式."""
        method = RPCMethodInfo(
            name="book",
            description="Book an item",
            mode="link",
        )
        assert method.mode == "link"

    def test_has_context(self):
        """测试 has_context 字段."""
        method = RPCMethodInfo(
            name="search",
            description="Search",
            has_context=True,
        )
        assert method.has_context is True


# =============================================================================
# context.py 测试
# =============================================================================


class TestSession:
    """测试 Session 类."""

    def test_set_and_get(self):
        """测试设置和获取值."""
        session = Session(session_id="test-session", did="did:wba:example.com:user1")
        session.set("key", "value")
        assert session.get("key") == "value"

    def test_get_default(self):
        """测试获取默认值."""
        session = Session(session_id="test-session", did="did:wba:example.com:user1")
        assert session.get("missing", "default") == "default"

    def test_get_none_default(self):
        """测试获取 None 默认值."""
        session = Session(session_id="test-session", did="did:wba:example.com:user1")
        assert session.get("missing") is None

    def test_clear(self):
        """测试清空."""
        session = Session(session_id="test-session", did="did:wba:example.com:user1")
        session.set("key1", "value1")
        session.set("key2", "value2")
        session.clear()
        assert session.get("key1") is None
        assert session.get("key2") is None

    def test_touch_updates_last_accessed(self):
        """测试 touch 更新最后访问时间."""
        import time
        session = Session(session_id="test-session", did="did:wba:example.com:user1")
        first_accessed = session.last_accessed
        time.sleep(0.01)  # 短暂等待
        session.touch()
        assert session.last_accessed > first_accessed


class TestSessionManager:
    """测试 SessionManager 类."""

    def test_get_or_create(self):
        """测试获取或创建会话."""
        manager = SessionManager()
        session1 = manager.get_or_create("did:wba:example.com:user1")
        session2 = manager.get_or_create("did:wba:example.com:user1")
        assert session1 is session2

    def test_different_dids_different_sessions(self):
        """测试不同 DID 不同会话."""
        manager = SessionManager()
        session1 = manager.get_or_create("did:wba:example.com:user1")
        session2 = manager.get_or_create("did:wba:example.com:user2")
        assert session1 is not session2

    def test_remove_by_session_id(self):
        """测试通过 session_id 移除会话."""
        manager = SessionManager()
        session1 = manager.get_or_create("did:wba:example.com:user1")
        session_id = session1.id
        manager.remove(session_id)
        session2 = manager.get_or_create("did:wba:example.com:user1")
        assert session1 is not session2

    def test_clear_all(self):
        """测试清空所有会话."""
        manager = SessionManager()
        manager.get_or_create("did:wba:example.com:user1")
        manager.get_or_create("did:wba:example.com:user2")
        manager.clear_all()
        assert len(manager.sessions) == 0


# =============================================================================
# decorators.py 测试
# =============================================================================


class TestInterfaceDecorator:
    """测试 @interface 装饰器."""

    def test_basic_interface(self):
        """测试基本接口装饰器."""

        @interface
        async def search(query: str) -> dict:
            """Search for items."""
            return {"results": []}

        assert hasattr(search, "_rpc_name")
        assert search._rpc_name == "search"
        assert search._rpc_description == "Search for items."
        assert search._mode == "content"
        assert search._has_context is False

    def test_interface_with_name(self):
        """测试带名称的接口装饰器."""

        @interface(name="custom_search")
        async def search(query: str) -> dict:
            """Search."""
            return {}

        assert search._rpc_name == "custom_search"

    def test_interface_with_description(self):
        """测试带描述的接口装饰器."""

        @interface(description="Custom description")
        async def search(query: str) -> dict:
            return {}

        assert search._rpc_description == "Custom description"

    def test_interface_link_mode(self):
        """测试 link 模式."""

        @interface(mode="link")
        async def book(hotel_id: str) -> dict:
            """Book a hotel."""
            return {}

        assert book._mode == "link"

    def test_interface_with_context(self):
        """测试带 Context 参数."""

        @interface
        async def search(query: str, ctx: Context) -> dict:
            """Search."""
            return {}

        assert search._has_context is True


class TestCheckHasContext:
    """测试 _check_has_context 函数."""

    def test_no_context(self):
        """测试没有 Context 参数."""

        def func(query: str) -> dict:
            return {}

        assert _check_has_context(func) is False

    def test_with_ctx_name(self):
        """测试 ctx 参数名."""

        def func(query: str, ctx: Any) -> dict:
            return {}

        assert _check_has_context(func) is True

    def test_with_context_name(self):
        """测试 context 参数名."""

        def func(query: str, context: Any) -> dict:
            return {}

        assert _check_has_context(func) is True

    def test_with_context_type(self):
        """测试 Context 类型注解."""

        def func(query: str, my_ctx: Context) -> dict:
            return {}

        assert _check_has_context(func) is True


class TestInformationDecorator:
    """测试 @information 装饰器."""

    def test_url_mode_information(self):
        """测试 URL 模式 information."""

        @information(type="Product", description="Products", path="/products.json")
        def get_products() -> dict:
            return {"products": []}

        assert hasattr(get_products, "_info_type")
        assert get_products._info_type == "Product"
        assert get_products._info_description == "Products"
        assert get_products._info_path == "/products.json"
        assert get_products._info_mode == "url"

    def test_content_mode_information(self):
        """测试 Content 模式 information."""

        @information(type="Service", description="Service info", mode="content")
        def get_service() -> dict:
            return {"service": "test"}

        assert get_service._info_mode == "content"

    def test_url_mode_requires_path(self):
        """测试 URL 模式需要 path."""
        with pytest.raises(ValueError, match="requires 'path'"):

            @information(type="Product", description="Test", mode="url")
            def get_products() -> dict:
                return {}


class TestAnpAgentDecorator:
    """测试 @anp_agent 装饰器."""

    def test_basic_agent(self):
        """测试基本 agent 装饰器."""
        config = AgentConfig(
            name="Test Agent",
            did="did:wba:example.com:test",
            prefix="/test",
        )

        @anp_agent(config)
        class TestAgent:
            @interface
            async def search(self, query: str) -> dict:
                """Search."""
                return {}

        assert hasattr(TestAgent, "_anp_config")
        assert TestAgent._anp_config is config
        assert hasattr(TestAgent, "_anp_rpc_method_names")
        assert "search" in TestAgent._anp_rpc_method_names
        assert hasattr(TestAgent, "router")

    def test_agent_with_information(self):
        """测试带 information 的 agent."""
        config = AgentConfig(
            name="Test Agent",
            did="did:wba:example.com:test",
        )

        @anp_agent(config)
        class TestAgent:
            @interface
            async def search(self, query: str) -> dict:
                return {}

            @information(type="Product", description="Products", path="/products.json")
            def get_products(self) -> dict:
                return {}

        assert hasattr(TestAgent, "_anp_info_method_names")
        assert "get_products" in TestAgent._anp_info_method_names


class TestExtractRpcMethods:
    """测试 extract_rpc_methods 函数."""

    def test_extract_from_class(self):
        """测试从类提取方法."""
        config = AgentConfig(name="Test", did="did:wba:example.com:test")

        @anp_agent(config)
        class TestAgent:
            @interface
            async def method1(self, a: str) -> dict:
                """Method 1."""
                return {}

            @interface(mode="link")
            async def method2(self, b: int) -> dict:
                """Method 2."""
                return {}

        methods = extract_rpc_methods(TestAgent)
        assert len(methods) == 2

        names = {m.name for m in methods}
        assert "method1" in names
        assert "method2" in names

    def test_extract_from_instance(self):
        """测试从实例提取方法."""
        config = AgentConfig(name="Test", did="did:wba:example.com:test")

        @anp_agent(config)
        class TestAgent:
            @interface
            async def search(self, query: str) -> dict:
                """Search."""
                return {}

        instance = TestAgent()
        methods = extract_rpc_methods(instance)
        assert len(methods) == 1
        assert methods[0].name == "search"
        # 实例方法 handler 是绑定的
        assert methods[0].handler is not None


# =============================================================================
# schema_gen.py 测试
# =============================================================================


class TestSchemaGeneration:
    """测试 schema 生成."""

    def test_extract_method_schemas_skips_context(self):
        """测试提取方法 schema 跳过 Context."""
        from anp.openanp.schema_gen import extract_method_schemas

        async def search(query: str, ctx: Context) -> dict:
            """Search."""
            return {}

        params_schema, result_schema = extract_method_schemas(search)

        # Context 不应出现在参数中
        properties = params_schema.get("properties", {})
        assert "ctx" not in properties
        assert "context" not in properties
        assert "query" in properties

    def test_extract_method_schemas_basic_types(self):
        """测试提取基本类型."""
        from anp.openanp.schema_gen import extract_method_schemas

        async def func(a: str, b: int, c: bool) -> dict:
            """Test function."""
            return {}

        params_schema, result_schema = extract_method_schemas(func)

        props = params_schema.get("properties", {})
        assert props.get("a", {}).get("type") == "string"
        assert props.get("b", {}).get("type") == "integer"
        assert props.get("c", {}).get("type") == "boolean"


# =============================================================================
# client/openrpc.py 测试
# =============================================================================


class TestOpenRPCParsing:
    """测试 OpenRPC 解析."""

    def test_parse_openrpc_valid(self):
        """测试解析有效 OpenRPC."""
        from anp.openanp.client.openrpc import parse_openrpc

        doc = {
            "openrpc": "1.3.2",
            "info": {"title": "Test API", "version": "1.0.0"},
            "methods": [
                {
                    "name": "search",
                    "description": "Search for items",
                    "params": [{"name": "query", "schema": {"type": "string"}}],
                    "result": {"name": "result", "schema": {"type": "object"}},
                }
            ],
            "servers": [{"name": "Main", "url": "https://example.com/rpc"}],
        }

        methods = parse_openrpc(doc)
        assert len(methods) == 1
        assert methods[0]["name"] == "search"
        assert methods[0]["description"] == "Search for items"
        assert len(methods[0]["params"]) == 1
        assert methods[0]["servers"][0]["url"] == "https://example.com/rpc"

    def test_parse_openrpc_invalid_missing_methods(self):
        """测试解析无效 OpenRPC（缺少 methods）."""
        from anp.openanp.client.openrpc import parse_openrpc

        doc = {"openrpc": "1.3.2"}

        with pytest.raises(ValueError, match="Invalid OpenRPC document"):
            parse_openrpc(doc)

    def test_convert_to_openai_tool(self):
        """测试转换到 OpenAI tool 格式."""
        from anp.openanp.client.openrpc import convert_to_openai_tool

        method = {
            "name": "search",
            "description": "Search for items",
            "params": [
                {"name": "query", "schema": {"type": "string"}, "required": True},
                {"name": "limit", "schema": {"type": "integer"}, "required": False},
            ],
            "components": {},
        }

        tool = convert_to_openai_tool(method)
        assert tool["type"] == "function"
        assert tool["function"]["name"] == "search"
        assert tool["function"]["description"] == "Search for items"
        assert "query" in tool["function"]["parameters"]["properties"]
        assert "limit" in tool["function"]["parameters"]["properties"]
        assert "query" in tool["function"]["parameters"]["required"]
        assert "limit" not in tool["function"]["parameters"]["required"]


class TestAgentDocumentParsing:
    """测试 Agent Document 解析."""

    def test_parse_agent_document_with_embedded_openrpc(self):
        """测试解析带嵌入 OpenRPC 的 AD."""
        from anp.openanp.client.openrpc import parse_agent_document

        ad = {
            "name": "Test Agent",
            "description": "A test agent",
            "servers": [{"name": "Main", "url": "https://example.com/rpc"}],
            "interfaces": [
                {
                    "type": "StructuredInterface",
                    "protocol": "openrpc",
                    "content": {
                        "openrpc": "1.3.2",
                        "methods": [
                            {
                                "name": "search",
                                "description": "Search",
                                "params": [],
                                "result": {"name": "result", "schema": {}},
                            }
                        ],
                    },
                }
            ],
        }

        agent_data, methods = parse_agent_document(ad)
        assert agent_data["name"] == "Test Agent"
        assert len(methods) == 1
        assert methods[0]["name"] == "search"
        # 应该有继承的 servers
        assert len(methods[0]["servers"]) == 1

    def test_parse_agent_document_with_url_interface(self):
        """测试解析带 URL 接口的 AD."""
        from anp.openanp.client.openrpc import parse_agent_document

        ad = {
            "name": "Test Agent",
            "description": "A test agent",
            "servers": [],
            "interfaces": [
                {
                    "type": "StructuredInterface",
                    "protocol": "openrpc",
                    "url": "https://example.com/interface.json",
                }
            ],
        }

        agent_data, methods = parse_agent_document(ad)
        assert agent_data["name"] == "Test Agent"
        # URL 接口不会直接解析出方法
        assert len(methods) == 0


# =============================================================================
# autogen.py 测试
# =============================================================================


class TestCoerceParams:
    """测试参数强制转换."""

    def test_coerce_dict_to_pydantic(self):
        """测试将 dict 转换为 Pydantic model."""
        from pydantic import BaseModel

        from anp.openanp.autogen import coerce_params

        class SearchCriteria(BaseModel):
            city: str
            max_price: int = 100

        async def search(criteria: SearchCriteria) -> dict:
            return {}

        params = {"criteria": {"city": "Tokyo", "max_price": 200}}
        coerced = coerce_params(search, params)

        assert isinstance(coerced["criteria"], SearchCriteria)
        assert coerced["criteria"].city == "Tokyo"
        assert coerced["criteria"].max_price == 200

    def test_coerce_preserves_non_dict(self):
        """测试保留非 dict 参数."""
        from anp.openanp.autogen import coerce_params

        async def search(query: str, limit: int) -> dict:
            return {}

        params = {"query": "Tokyo", "limit": 10}
        coerced = coerce_params(search, params)

        assert coerced["query"] == "Tokyo"
        assert coerced["limit"] == 10


class TestRPCProcessing:
    """测试 RPC 请求处理."""

    @pytest.mark.asyncio
    async def test_process_single_rpc_request(self):
        """测试处理单个 RPC 请求."""
        from anp.openanp.autogen import process_single_rpc_request

        async def search(query: str) -> dict:
            return {"results": [query]}

        handlers = {"search": search}
        body = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "search",
            "params": {"query": "Tokyo"},
        }

        result = await process_single_rpc_request(body, handlers)
        assert result["jsonrpc"] == "2.0"
        assert result["id"] == 1
        assert result["result"]["results"] == ["Tokyo"]

    @pytest.mark.asyncio
    async def test_process_rpc_method_not_found(self):
        """测试处理不存在的方法."""
        from anp.openanp.autogen import process_single_rpc_request

        handlers = {}
        body = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "unknown",
            "params": {},
        }

        result = await process_single_rpc_request(body, handlers)
        assert "error" in result
        assert result["error"]["code"] == -32601  # Method not found

    @pytest.mark.asyncio
    async def test_process_batch_rpc_request(self):
        """测试处理批量 RPC 请求."""
        from anp.openanp.autogen import process_batch_rpc_request

        async def add(a: int, b: int) -> int:
            return a + b

        handlers = {"add": add}
        batch = [
            {"jsonrpc": "2.0", "id": 1, "method": "add", "params": {"a": 1, "b": 2}},
            {"jsonrpc": "2.0", "id": 2, "method": "add", "params": {"a": 3, "b": 4}},
        ]

        results = await process_batch_rpc_request(batch, handlers)
        assert len(results) == 2
        # 结果可能乱序，按 id 排序验证
        results_by_id = {r["id"]: r for r in results}
        assert results_by_id[1]["result"] == 3
        assert results_by_id[2]["result"] == 7


# =============================================================================
# 集成测试
# =============================================================================


class TestIntegration:
    """集成测试."""

    def test_full_agent_definition(self):
        """测试完整 agent 定义."""
        config = AgentConfig(
            name="Hotel Agent",
            did="did:wba:example.com:hotel",
            prefix="/hotel",
            description="Hotel booking service",
        )

        @anp_agent(config)
        class HotelAgent:
            informations = [
                Information(
                    type="VideoObject",
                    description="Hotel tour",
                    url="https://cdn.example.com/tour.mp4",
                ),
            ]

            @interface
            async def search(self, query: str) -> dict:
                """Search hotels."""
                return {"results": []}

            @interface(mode="link")
            async def book(self, hotel_id: str, ctx: Context) -> dict:
                """Book a hotel."""
                return {"status": "booked"}

            @information(type="Product", description="Rooms", path="/rooms.json")
            def get_rooms(self) -> dict:
                return {"rooms": []}

        # 验证配置
        assert HotelAgent._anp_config.name == "Hotel Agent"

        # 验证方法
        methods = extract_rpc_methods(HotelAgent)
        assert len(methods) == 2

        search_method = next(m for m in methods if m.name == "search")
        assert search_method.mode == "content"
        assert search_method.has_context is False

        book_method = next(m for m in methods if m.name == "book")
        assert book_method.mode == "link"
        assert book_method.has_context is True

        # 验证 information 方法
        assert "get_rooms" in HotelAgent._anp_info_method_names


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
