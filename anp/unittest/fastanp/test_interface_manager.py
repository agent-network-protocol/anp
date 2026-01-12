"""FastANP InterfaceManager Tests.

This module tests interface registration and OpenRPC document generation:
- Function registration and name uniqueness
- OpenRPC document generation
- InterfaceProxy creation and properties
- Context parameter detection and injection
- Pydantic model schema extraction
"""

import unittest
from typing import Dict, List

from pydantic import BaseModel

from anp.fastanp.interface_manager import InterfaceManager, InterfaceProxy, RegisteredFunction
from anp.fastanp.context import Context


class TestModel(BaseModel):
    """Test Pydantic model for testing."""
    id: str
    value: int


class TestRegisterFunction(unittest.TestCase):
    """测试函数注册功能"""

    def setUp(self):
        """每个测试前创建新的 InterfaceManager"""
        self.manager = InterfaceManager(
            api_title="Test API",
            api_version="1.0.0",
            api_description="Test API Description"
        )

    def test_register_simple_function(self):
        """测试注册简单函数"""
        def test_func(name: str) -> str:
            """Test function docstring"""
            return f"Hello {name}"

        registered = self.manager.register_function(
            func=test_func,
            path="/test",
            description="Test function"
        )

        self.assertIsNotNone(registered)
        self.assertEqual(registered.name, "test_func")
        self.assertEqual(registered.path, "/test")
        self.assertEqual(registered.description, "Test function")
        self.assertIn(test_func, self.manager.functions)

    def test_register_function_duplicate_name_fails(self):
        """测试注册重复函数名应该失败"""
        def test_func() -> str:
            return "test"

        # 第一次注册应该成功
        self.manager.register_function(
            func=test_func,
            path="/test1"
        )

        # 使用相同名称的第二个函数应该失败
        def test_func() -> str:  # noqa: F811
            return "test2"

        with self.assertRaises(ValueError) as context:
            self.manager.register_function(
                func=test_func,
                path="/test2"
            )

        self.assertIn("already registered", str(context.exception))

    def test_register_function_uses_docstring_if_no_description(self):
        """测试如果未提供描述则使用 docstring"""
        def test_func():
            """This is a docstring"""
            pass

        registered = self.manager.register_function(
            func=test_func,
            path="/test"
        )

        self.assertEqual(registered.description, "This is a docstring")

    def test_register_function_with_context_param(self):
        """测试注册带 Context 参数的函数"""
        def test_func(ctx: Context, name: str) -> str:
            return f"Hello {name}"

        registered = self.manager.register_function(
            func=test_func,
            path="/test"
        )

        # Context 参数应该被检测到
        self.assertTrue(registered.has_context_param)

        # Context 不应该出现在 params 中
        param_names = [p["name"] for p in registered.params]
        self.assertNotIn("ctx", param_names)

    def test_register_function_with_pydantic_model(self):
        """测试注册带 Pydantic 模型参数的函数"""
        def test_func(data: TestModel) -> Dict:
            return {"id": data.id, "value": data.value}

        registered = self.manager.register_function(
            func=test_func,
            path="/test"
        )

        # Pydantic 模型应该被提取
        self.assertIn("TestModel", registered.pydantic_models)
        self.assertEqual(registered.pydantic_models["TestModel"], TestModel)


class TestOpenRPCGeneration(unittest.TestCase):
    """测试 OpenRPC 文档生成"""

    def setUp(self):
        """每个测试前创建新的 InterfaceManager"""
        self.manager = InterfaceManager(
            api_title="Test API",
            api_version="1.0.0"
        )

    def test_generate_openrpc_basic(self):
        """测试生成基本的 OpenRPC 文档"""
        def add(a: int, b: int) -> int:
            """Add two numbers"""
            return a + b

        registered = self.manager.register_function(
            func=add,
            path="/add-interface"
        )

        doc = self.manager.generate_openrpc_for_function(
            registered_func=registered,
            base_url="https://example.com"
        )

        # 验证 OpenRPC 结构
        self.assertEqual(doc["openrpc"], "1.3.2")
        self.assertEqual(doc["info"]["title"], "add")
        self.assertEqual(doc["info"]["version"], "1.0.0")

        # 验证方法定义
        self.assertEqual(len(doc["methods"]), 1)
        method = doc["methods"][0]
        self.assertEqual(method["name"], "add")

        # 验证参数
        self.assertEqual(len(method["params"]), 2)
        param_names = [p["name"] for p in method["params"]]
        self.assertIn("a", param_names)
        self.assertIn("b", param_names)

    def test_generate_openrpc_with_pydantic_schemas(self):
        """测试生成包含 Pydantic 模型的 OpenRPC 文档"""
        def process_data(data: TestModel) -> Dict:
            """Process test data"""
            return {"id": data.id}

        registered = self.manager.register_function(
            func=process_data,
            path="/process"
        )

        doc = self.manager.generate_openrpc_for_function(
            registered_func=registered,
            base_url="https://example.com"
        )

        # 验证 schemas 包含 TestModel
        self.assertIn("components", doc)
        self.assertIn("schemas", doc["components"])
        self.assertIn("TestModel", doc["components"]["schemas"])

    def test_generate_openrpc_servers(self):
        """测试 OpenRPC 文档中的 servers 字段"""
        def test_func() -> str:
            return "test"

        registered = self.manager.register_function(
            func=test_func,
            path="/test"
        )

        doc = self.manager.generate_openrpc_for_function(
            registered_func=registered,
            base_url="https://example.com",
            rpc_endpoint="/rpc"
        )

        # 验证 servers 配置
        self.assertEqual(len(doc["servers"]), 1)
        server = doc["servers"][0]
        self.assertEqual(server["url"], "https://example.com/rpc")

    def test_generate_openrpc_security(self):
        """测试 OpenRPC 文档中的 security 配置"""
        def test_func() -> str:
            return "test"

        registered = self.manager.register_function(
            func=test_func,
            path="/test"
        )

        doc = self.manager.generate_openrpc_for_function(
            registered_func=registered,
            base_url="https://example.com"
        )

        # 验证 security 配置
        self.assertIn("security", doc)
        self.assertEqual(doc["security"], [{"didwba": []}])

        # 验证 securitySchemes
        self.assertIn("components", doc)
        self.assertIn("securitySchemes", doc["components"])
        self.assertIn("didwba", doc["components"]["securitySchemes"])


class TestInterfaceProxy(unittest.TestCase):
    """测试 InterfaceProxy 功能"""

    def setUp(self):
        """每个测试前创建新的 InterfaceManager"""
        self.manager = InterfaceManager()

    def test_create_interface_proxy(self):
        """测试创建 InterfaceProxy"""
        def test_func(name: str) -> str:
            """Test function"""
            return f"Hello {name}"

        self.manager.register_function(
            func=test_func,
            path="/test",
            description="Test description"
        )

        proxy = self.manager.create_interface_proxy(
            func=test_func,
            base_url="https://example.com"
        )

        self.assertIsInstance(proxy, InterfaceProxy)
        self.assertEqual(proxy.func, test_func)
        self.assertEqual(proxy.path, "/test")
        self.assertEqual(proxy.base_url, "https://example.com")

    def test_interface_proxy_link_summary(self):
        """测试 InterfaceProxy.link_summary"""
        def test_func() -> str:
            """Test function"""
            return "test"

        self.manager.register_function(
            func=test_func,
            path="/test-interface",
            description="Test description"
        )

        proxy = self.manager.create_interface_proxy(
            func=test_func,
            base_url="https://example.com"
        )

        link = proxy.link_summary

        self.assertEqual(link["type"], "StructuredInterface")
        self.assertEqual(link["protocol"], "openrpc")
        self.assertEqual(link["description"], "Test description")
        self.assertEqual(link["url"], "https://example.com/test-interface")

    def test_interface_proxy_content(self):
        """测试 InterfaceProxy.content 包含嵌入的 OpenRPC 文档"""
        def test_func() -> str:
            """Test function"""
            return "test"

        self.manager.register_function(
            func=test_func,
            path="/test"
        )

        proxy = self.manager.create_interface_proxy(
            func=test_func,
            base_url="https://example.com"
        )

        content = proxy.content

        self.assertEqual(content["type"], "StructuredInterface")
        self.assertEqual(content["protocol"], "openrpc")
        self.assertIn("content", content)
        # content 应该包含完整的 OpenRPC 文档
        self.assertIn("openrpc", content["content"])
        self.assertIn("methods", content["content"])

    def test_interface_proxy_openrpc_doc(self):
        """测试 InterfaceProxy.openrpc_doc 返回原始文档"""
        def test_func() -> str:
            return "test"

        self.manager.register_function(
            func=test_func,
            path="/test"
        )

        proxy = self.manager.create_interface_proxy(
            func=test_func,
            base_url="https://example.com"
        )

        doc = proxy.openrpc_doc

        self.assertIsInstance(doc, dict)
        self.assertEqual(doc["openrpc"], "1.3.2")
        self.assertIn("methods", doc)


class TestParameterParsing(unittest.TestCase):
    """测试参数解析功能"""

    def setUp(self):
        """每个测试前创建新的 InterfaceManager"""
        self.manager = InterfaceManager()

    def test_parse_basic_types(self):
        """测试解析基本类型参数"""
        def test_func(name: str, age: int, active: bool) -> Dict:
            return {}

        registered = self.manager.register_function(
            func=test_func,
            path="/test"
        )

        # 检查参数类型
        params = {p["name"]: p for p in registered.params}
        self.assertIn("name", params)
        self.assertIn("age", params)
        self.assertIn("active", params)

    def test_parse_optional_parameters(self):
        """测试解析可选参数"""
        def test_func(required: str, optional: str = "default") -> str:
            return required + optional

        registered = self.manager.register_function(
            func=test_func,
            path="/test"
        )

        params = {p["name"]: p for p in registered.params}
        self.assertTrue(params["required"]["required"])
        self.assertFalse(params["optional"]["required"])

    def test_parse_list_type(self):
        """测试解析列表类型参数"""
        def test_func(items: List[str]) -> int:
            return len(items)

        registered = self.manager.register_function(
            func=test_func,
            path="/test"
        )

        # 验证参数已被解析
        self.assertEqual(len(registered.params), 1)
        self.assertEqual(registered.params[0]["name"], "items")


if __name__ == "__main__":
    unittest.main()
