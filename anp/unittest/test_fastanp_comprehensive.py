#!/usr/bin/env python3
"""
FastANP 插件化重构综合测试用例

测试所有主要功能，包括：
- ad.json 获取功能
- information 获取功能
- Interface 获取功能
- Interface 调用功能
- Context 自动注入机制
- 中间件认证功能
- 真实 DID WBA 认证流程
"""

import asyncio
import copy
import json
import sys
from pathlib import Path
from typing import Any, Dict

from fastapi import FastAPI
from fastapi.testclient import TestClient
from pydantic import BaseModel

# 添加项目根目录到 Python 路径
project_root = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(project_root))

from anp.authentication import DIDWbaAuthHeader
from anp.authentication import did_wba_verifier as verifier_module
from anp.authentication.did_wba_verifier import DidWbaVerifierConfig
from anp.fastanp import FastANP
from anp.fastanp.context import Context


class TestData(BaseModel):
    """测试用的 Pydantic 模型"""
    name: str
    value: int


# 测试配置
TEST_BASE_URL = "http://localhost:8000"
TEST_AGENT_ID = "test-agent"


# Shared docs resources
DOCS_DIR = project_root / "docs"
TEST_DID_DOCUMENT_PATH = DOCS_DIR / "did_public" / "public-did-doc.json"
TEST_DID_PRIVATE_KEY_PATH = DOCS_DIR / "did_public" / "public-private-key.pem"
TEST_JWT_PRIVATE_KEY_PATH = DOCS_DIR / "jwt_rs256" / "RS256-private.pem"
TEST_JWT_PUBLIC_KEY_PATH = DOCS_DIR / "jwt_rs256" / "RS256-public.pem"

with open(TEST_DID_DOCUMENT_PATH, "r", encoding="utf-8") as did_file:
    DID_DOCUMENT = json.load(did_file)
    TEST_DID = DID_DOCUMENT["id"]

with open(TEST_JWT_PRIVATE_KEY_PATH, "r", encoding="utf-8") as private_key_file:
    TEST_JWT_PRIVATE_KEY = private_key_file.read()

with open(TEST_JWT_PUBLIC_KEY_PATH, "r", encoding="utf-8") as public_key_file:
    TEST_JWT_PUBLIC_KEY = public_key_file.read()


class TestFastANPComprehensive:
    """FastANP 综合测试类"""

    def __init__(self):
        """初始化测试类"""
        # 创建 FastAPI 应用
        self.app = FastAPI(title="Test FastANP", version="1.0.0")

        # 初始化 FastANP 插件
        self.anp = FastANP(
            app=self.app,
            name="Test Agent",
            description="A test agent for FastANP comprehensive testing",
            base_url=TEST_BASE_URL,
            did=TEST_DID,
            owner={"name": "Test Owner", "email": "owner@example.com"},
            jsonrpc_server_url="/rpc",
            enable_auth_middleware=False,  # 测试时先关闭中间件
            api_version="1.0.0"
        )

        # 注册测试接口
        self._register_test_interfaces()

        # 注册 ad.json 端点
        self._register_ad_endpoint()

        # 注册 information 端点
        self._register_information_endpoints()

        # 测试客户端
        self.client = None

    def _register_test_interfaces(self):
        """注册测试接口"""

        @self.anp.interface("/info/simple_hello.json", description="Simple hello interface")
        def simple_hello(name: str) -> Dict[str, str]:
            """
            Simple hello interface without context

            Args:
                name: Name to greet

            Returns:
                Greeting message
            """
            return {"message": f"Hello, {name}!"}

        @self.anp.interface("/info/context_hello.json", description="Hello with context injection")
        def context_hello(name: str, ctx: Context) -> Dict[str, Any]:
            """
            Hello interface with context injection

            Args:
                name: Name to greet
                ctx: Automatically injected context

            Returns:
                Greeting message with context info
            """
            return {
                "message": f"Hello, {name}!",
                "session_id": ctx.session.id[:8] if ctx.session else "no-session",
                "did": ctx.did,
                "client_host": ctx.client_host
            }

        @self.anp.interface("/info/process_data.json", description="Process data with Pydantic model")
        def process_data(data: TestData) -> Dict[str, Any]:
            """
            Process data using Pydantic model

            Args:
                data: Input data

            Returns:
                Processed result
            """
            return {
                "processed": True,
                "input_name": data.name,
                "input_value": data.value,
                "computed": data.value * 2
            }

        @self.anp.interface("/info/async_operation.json", description="Async operation test")
        async def async_operation(delay: float = 0.1) -> Dict[str, Any]:
            """
            Async operation test

            Args:
                delay: Delay in seconds

            Returns:
                Operation result
            """
            await asyncio.sleep(delay)
            return {
                "status": "completed",
                "delay": delay,
                "timestamp": asyncio.get_event_loop().time()
            }

    def _register_ad_endpoint(self):
        """注册 ad.json 端点"""

        @self.app.get(f"/{TEST_AGENT_ID}/ad.json")
        def get_agent_description():
            """获取 Agent Description"""
            # 获取公共头部
            ad = self.anp.get_common_header(ad_url=f"{TEST_BASE_URL}/{TEST_AGENT_ID}/ad.json")

            # 添加自定义 Information
            ad["Infomations"] = [
                {
                    "type": "Product",
                    "description": "Test product information",
                    "url": f"{TEST_BASE_URL}/{TEST_AGENT_ID}/product.json"
                },
                {
                    "type": "Service",
                    "description": "Test service information",
                    "url": f"{TEST_BASE_URL}/{TEST_AGENT_ID}/service.json"
                }
            ]

            # 添加 Interface（链接模式）
            # 通过函数名找到对应的函数对象
            interfaces = []
            for func_name in ["simple_hello", "context_hello", "process_data", "async_operation"]:
                for func in self.anp.interface_manager.functions.keys():
                    if func.__name__ == func_name:
                        proxy = self.anp.interfaces[func]
                        interfaces.append(proxy.link_summary)
                        break

            ad["interfaces"] = interfaces

            return ad

    def _register_information_endpoints(self):
        """注册 information 端点"""

        @self.app.get(f"/{TEST_AGENT_ID}/product.json")
        def get_product_info():
            """获取产品信息"""
            return {
                "name": "Test Product",
                "version": "1.0.0",
                "description": "A test product for FastANP",
                "features": ["feature1", "feature2", "feature3"]
            }

        @self.app.get(f"/{TEST_AGENT_ID}/service.json")
        def get_service_info():
            """获取服务信息"""
            return {
                "name": "Test Service",
                "status": "active",
                "endpoints": [
                    {"name": "hello", "path": "/info/simple_hello.json"},
                    {"name": "context_hello", "path": "/info/context_hello.json"}
                ]
            }

    def setup_client(self):
        """设置测试客户端"""
        # 创建 TestClient
        self.client = TestClient(self.app)

    def test_ad_json_endpoint(self):
        """测试 ad.json 端点"""
        self.setup_client()

        try:
            # 获取 ad.json
            response = self.client.get(f"/{TEST_AGENT_ID}/ad.json")

            # 验证响应
            assert response.status_code == 200
            data = response.json()

            # 验证基本字段
            assert data["protocolType"] == "ANP"
            assert data["type"] == "AgentDescription"
            assert data["name"] == "Test Agent"
            assert data["did"] is not None

            # 验证 Information
            assert "Infomations" in data
            assert len(data["Infomations"]) == 2

            # 验证 Interface
            assert "interfaces" in data
            assert len(data["interfaces"]) == 4

            print("✓ ad.json endpoint test passed")

        finally:
            self.client.close()

    def test_information_endpoints(self):
        """测试 information 端点"""
        self.setup_client()

        try:
            # 测试产品信息端点
            response = self.client.get(f"/{TEST_AGENT_ID}/product.json")
            assert response.status_code == 200
            product_data = response.json()
            assert product_data["name"] == "Test Product"
            assert "features" in product_data

            # 测试服务信息端点
            response = self.client.get(f"/{TEST_AGENT_ID}/service.json")
            assert response.status_code == 200
            service_data = response.json()
            assert service_data["name"] == "Test Service"
            assert "endpoints" in service_data

            print("✓ Information endpoints test passed")

        finally:
            self.client.close()

    def test_interface_openrpc_endpoints(self):
        """测试 Interface 的 OpenRPC 文档端点"""
        self.setup_client()

        try:
            # 测试 simple_hello 的 OpenRPC 文档
            response = self.client.get("/info/simple_hello.json")
            assert response.status_code == 200
            openrpc_doc = response.json()
            assert openrpc_doc["openrpc"] == "1.3.2"
            assert openrpc_doc["info"]["title"] == "simple_hello"

            # 测试 context_hello 的 OpenRPC 文档
            response = self.client.get("/info/context_hello.json")
            assert response.status_code == 200
            openrpc_doc = response.json()
            assert openrpc_doc["openrpc"] == "1.3.2"

            print("✓ Interface OpenRPC endpoints test passed")

        finally:
            self.client.close()

    def test_jsonrpc_simple_hello(self):
        """测试 JSON-RPC 调用 simple_hello"""
        self.setup_client()

        try:
            # 调用 simple_hello
            payload = {
                "jsonrpc": "2.0",
                "method": "simple_hello",
                "params": {"name": "World"},
                "id": 1
            }

            response = self.client.post("/rpc", json=payload)
            assert response.status_code == 200

            result = response.json()
            assert result["jsonrpc"] == "2.0"
            assert "result" in result
            assert result["result"]["message"] == "Hello, World!"

            print("✓ JSON-RPC simple_hello test passed")

        finally:
            self.client.close()

    def test_jsonrpc_context_injection(self):
        """测试 JSON-RPC 调用中的 Context 注入"""
        self.setup_client()

        try:
            # 调用 context_hello（需要认证，但测试时没有认证信息）
            payload = {
                "jsonrpc": "2.0",
                "method": "context_hello",
                "params": {"name": "ContextTest"},
                "id": 1
            }

            response = self.client.post("/rpc", json=payload)
            assert response.status_code == 200

            result = response.json()
            assert result["jsonrpc"] == "2.0"
            assert "result" in result

            # 验证 Context 信息（匿名会话）
            result_data = result["result"]
            assert result_data["message"] == "Hello, ContextTest!"
            assert "session_id" in result_data
            assert result_data["did"] == "anonymous"

            print("✓ JSON-RPC context injection test passed")

        finally:
            self.client.close()

    def test_jsonrpc_pydantic_model(self):
        """测试 JSON-RPC 调用中的 Pydantic 模型"""
        self.setup_client()

        try:
            # 调用 process_data 使用 Pydantic 模型
            payload = {
                "jsonrpc": "2.0",
                "method": "process_data",
                "params": {
                    "data": {
                        "name": "test_data",
                        "value": 42
                    }
                },
                "id": 1
            }

            response = self.client.post("/rpc", json=payload)
            assert response.status_code == 200

            result = response.json()
            assert result["jsonrpc"] == "2.0"
            assert "result" in result

            result_data = result["result"]
            assert result_data["processed"] is True
            assert result_data["input_name"] == "test_data"
            assert result_data["input_value"] == 42
            assert result_data["computed"] == 84

            print("✓ JSON-RPC Pydantic model test passed")

        finally:
            self.client.close()

    def test_jsonrpc_async_operation(self):
        """测试 JSON-RPC 调用异步操作"""
        self.setup_client()

        try:
            # 调用 async_operation
            payload = {
                "jsonrpc": "2.0",
                "method": "async_operation",
                "params": {"delay": 0.01},
                "id": 1
            }

            response = self.client.post("/rpc", json=payload)
            assert response.status_code == 200

            result = response.json()
            assert result["jsonrpc"] == "2.0"
            assert "result" in result

            result_data = result["result"]
            assert result_data["status"] == "completed"
            assert result_data["delay"] == 0.01
            assert "timestamp" in result_data

            print("✓ JSON-RPC async operation test passed")

        finally:
            self.client.close()

    def test_interface_proxy_access(self):
        """测试 InterfaceProxy 访问"""
        # 测试 link_summary
        for func_name in ["simple_hello", "context_hello", "process_data", "async_operation"]:
            # 通过函数名找到对应的函数对象
            func = None
            for f in self.anp.interface_manager.functions.keys():
                if f.__name__ == func_name:
                    func = f
                    break

            if func:
                proxy = self.anp.interfaces[func]

                # 测试 link_summary
                link_summary = proxy.link_summary
                assert link_summary["type"] == "StructuredInterface"
                assert link_summary["protocol"] == "openrpc"
                assert "url" in link_summary

                # 测试 content
                content = proxy.content
                assert content["type"] == "StructuredInterface"
                assert "content" in content

                # 测试 openrpc_doc
                openrpc_doc = proxy.openrpc_doc
                assert openrpc_doc["openrpc"] == "1.3.2"

        print("✓ InterfaceProxy access test passed")

    def test_auth_excluded_paths(self):
        """测试认证排除路径配置"""
        # 验证认证排除路径配置正确
        from anp.fastanp.middleware import EXEMPT_PATHS

        expected_paths = [
            "/favicon.ico",
            "/health",
            "/docs",
            "*/ad.json",
            "/info/*",  # OpenRPC documents
        ]

        assert EXEMPT_PATHS == expected_paths
        print("✓ Auth excluded paths configuration test passed")
    
    def test_auth_middleware_enforcement(self):
        """测试认证中间件强制认证"""
        # 创建启用了认证中间件的应用
        app = FastAPI()

        # 创建认证配置
        auth_config = DidWbaVerifierConfig(
            jwt_private_key=TEST_JWT_PRIVATE_KEY,
            jwt_public_key=TEST_JWT_PUBLIC_KEY,
            jwt_algorithm="RS256"
        )

        anp = FastANP(
            app=app,
            name="Auth Test Agent",
            description="Test auth middleware",
            base_url=TEST_BASE_URL,
            did=TEST_DID,
            enable_auth_middleware=True,  # Enable strict auth
            auth_config=auth_config
        )
        
        @app.get("/ad.json")
        def get_ad():
            return {"name": "test"}
        
        @app.get("/custom-api")
        def custom_api():
            return {"data": "sensitive"}
        
        @anp.interface("/info/secure_method.json")
        def secure_method(param: str) -> Dict[str, str]:
            return {"result": param}
        
        client = TestClient(app)
        
        # Test 1: Excluded paths work without auth
        print("   Testing excluded paths without auth...")
        
        # /ad.json
        response = client.get("/ad.json")
        assert response.status_code == 200
        print("   ✓ /ad.json accessible without auth")
        
        # /info/* (OpenRPC docs)
        response = client.get("/info/secure_method.json")
        assert response.status_code == 200
        assert "openrpc" in response.json()
        print("   ✓ /info/secure_method.json (OpenRPC) accessible without auth")
        
        # Test 2: Protected endpoints require auth
        print("   Testing protected endpoints require auth...")
        
        # /rpc without auth
        response = client.post("/rpc", json={
            "jsonrpc": "2.0",
            "id": 1,
            "method": "secure_method",
            "params": {"param": "test"}
        })
        assert response.status_code == 401
        error_data = response.json()
        assert "detail" in error_data
        assert "Missing authorization header" in error_data["detail"]
        print("   ✓ /rpc returns 401 without auth")
        
        # Custom endpoint without auth
        response = client.get("/custom-api")
        assert response.status_code == 401
        print("   ✓ /custom-api returns 401 without auth")
        
        # Test 3: Invalid Authorization header
        print("   Testing invalid Authorization header...")
        response = client.post(
            "/rpc",
            json={"jsonrpc": "2.0", "id": 2, "method": "secure_method", "params": {"param": "test"}},
            headers={"Authorization": "Bearer invalid-token"}
        )
        assert response.status_code in [401, 403, 500]
        error_data = response.json()
        assert "detail" in error_data
        print(f"   ✓ Invalid auth header returns {response.status_code}")

        # Test 4: Malformed Authorization header
        print("   Testing malformed Authorization header...")
        response = client.post(
            "/rpc",
            json={"jsonrpc": "2.0", "id": 3, "method": "secure_method", "params": {"param": "test"}},
            headers={"Authorization": "NotEvenClose"}
        )
        assert response.status_code in [401, 403, 500]
        print(f"   ✓ Malformed auth header returns {response.status_code}")
        
        print("✓ Auth middleware enforcement test passed")
    
    def test_real_did_wba_authentication(self):
        """测试真实的 DID WBA 认证流程"""
        print("\n🔐 测试真实 DID WBA 认证...")

        # Use shared DID document and JWT keys shipped in docs
        did_document = copy.deepcopy(DID_DOCUMENT)

        # Setup local DID resolver
        async def local_resolver(did: str):
            if did != did_document["id"]:
                raise ValueError(f"Unsupported DID: {did}")
            return did_document

        # Temporarily replace the resolver
        original_resolver = verifier_module.resolve_did_wba_document
        verifier_module.resolve_did_wba_document = local_resolver

        try:
            # Create auth config
            auth_config = DidWbaVerifierConfig(
                jwt_private_key=TEST_JWT_PRIVATE_KEY,
                jwt_public_key=TEST_JWT_PUBLIC_KEY,
                jwt_algorithm="RS256"
            )

            # Create app with real auth
            app = FastAPI()
            anp = FastANP(
                app=app,
                name="Secure Agent",
                description="Agent with real DID WBA authentication",
                base_url=TEST_BASE_URL,
                did=did_document["id"],
                enable_auth_middleware=True,
                auth_config=auth_config
            )
            
            @app.get("/ad.json")
            def get_ad():
                return anp.get_common_header()
            
            @anp.interface("/info/authenticated_method.json")
            def authenticated_method(message: str, ctx: Context) -> Dict[str, Any]:
                """Authenticated method with context."""
                visit_count = ctx.session.get("visits", 0) + 1
                ctx.session.set("visits", visit_count)
                
                return {
                    "message": message,
                    "did": ctx.did,
                    "session_id": ctx.session.id,
                    "visit_count": visit_count,
                    "authenticated": True
                }
            
            # Create authenticator
            authenticator = DIDWbaAuthHeader(
                did_document_path=str(TEST_DID_DOCUMENT_PATH),
                private_key_path=str(TEST_DID_PRIVATE_KEY_PATH)
            )
            
            client = TestClient(app, base_url=TEST_BASE_URL)
            
            # Test without auth - should fail
            print("   测试无认证访问...")
            response = client.post("/rpc", json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "authenticated_method",
                "params": {"message": "test"}
            })
            assert response.status_code == 401
            print("   ✓ 无认证访问被正确拦截")
            
            # Generate DID WBA auth header
            print("   测试 DID WBA 认证...")
            server_url = f"{TEST_BASE_URL}/resource"
            auth_headers = authenticator.get_auth_header(server_url, force_new=True)
            authorization = auth_headers["Authorization"]
            
            # Test with DID WBA auth
            response = client.post(
                "/rpc",
                json={
                    "jsonrpc": "2.0",
                    "id": 2,
                    "method": "authenticated_method",
                    "params": {"message": "Hello with auth"}
                },
                headers={"Authorization": authorization}
            )

            if response.status_code != 200:
                print(f"   ✗ DID WBA 认证失败: {response.status_code}")
                print(f"   响应: {response.text}")
            assert response.status_code == 200
            result1 = response.json()["result"]
            assert result1["authenticated"] is True
            assert result1["visit_count"] == 1
            assert result1["did"] == did_document["id"]
            session_id1 = result1["session_id"]
            print(f"   ✓ DID WBA 认证成功，会话已创建: {session_id1[:8]}...")
            
            # Second call with new auth header but same DID
            auth_headers2 = authenticator.get_auth_header(server_url, force_new=True)
            authorization2 = auth_headers2["Authorization"]
            
            response = client.post(
                "/rpc",
                json={
                    "jsonrpc": "2.0",
                    "id": 3,
                    "method": "authenticated_method",
                    "params": {"message": "Second call"}
                },
                headers={"Authorization": authorization2}
            )
            
            assert response.status_code == 200
            result2 = response.json()["result"]
            assert result2["visit_count"] == 2  # Session shared
            assert result2["session_id"] == session_id1  # Same session
            assert result2["did"] == did_document["id"]
            print(f"   ✓ 相同 DID 共享会话，访问次数={result2['visit_count']}")
            
            # Test public endpoints still accessible
            response = client.get("/ad.json")
            assert response.status_code == 200
            print("   ✓ 公开端点无需认证")
            
            print("✓ Real DID WBA authentication test passed")
            
        finally:
            # Restore original resolver
            verifier_module.resolve_did_wba_document = original_resolver


def run_all_tests():
    """运行所有测试"""
    print("🚀 开始 FastANP 综合测试...")

    tester = TestFastANPComprehensive()

    # 运行各个测试
    tester.test_ad_json_endpoint()
    tester.test_information_endpoints()
    tester.test_interface_openrpc_endpoints()
    tester.test_jsonrpc_simple_hello()
    tester.test_jsonrpc_context_injection()
    tester.test_jsonrpc_pydantic_model()
    tester.test_jsonrpc_async_operation()
    tester.test_interface_proxy_access()
    tester.test_auth_excluded_paths()
    tester.test_auth_middleware_enforcement()
    tester.test_real_did_wba_authentication()

    print("\n🎉 所有测试通过！FastANP 插件化重构实现正确。")


if __name__ == "__main__":
    # 运行测试
    run_all_tests()
