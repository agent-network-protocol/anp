#!/usr/bin/env python3
"""
Integration test for FastANP refactored implementation.

Tests the core functionality of the new plugin-based design.
"""

import sys
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent.parent.parent.parent
sys.path.insert(0, str(project_root))

from fastapi import FastAPI
from fastapi.testclient import TestClient
from pydantic import BaseModel

from anp.fastanp import Context, FastANP


def test_basic_setup():
    """Test basic FastANP setup."""
    print("Testing basic setup...")
    
    app = FastAPI()
    anp = FastANP(
        app=app,
        name="Test Agent",
        description="Test agent description",
        base_url="https://test.example.com",
        did="did:wba:test.example.com:agent:test",
        did_document_path=str(project_root / "docs" / "did_public" / "public-did-doc.json"),
        private_key_path=str(project_root / "docs" / "jwt_rs256" / "private_key.pem"),
        public_key_path=str(project_root / "docs" / "jwt_rs256" / "public_key.pem"),
        require_auth=False
    )
    
    assert anp.name == "Test Agent"
    assert anp.base_url == "https://test.example.com"
    assert anp.did == "did:wba:test.example.com:agent:test"
    print("✓ Basic setup works")


def test_interface_registration():
    """Test interface registration and decoration."""
    print("\nTesting interface registration...")
    
    app = FastAPI()
    anp = FastANP(
        app=app,
        name="Test Agent",
        description="Test",
        base_url="https://test.example.com",
        did="did:wba:test.example.com:agent:test",
        did_document_path=str(project_root / "docs" / "did_public" / "public-did-doc.json"),
        private_key_path=str(project_root / "docs" / "jwt_rs256" / "private_key.pem"),
        public_key_path=str(project_root / "docs" / "jwt_rs256" / "public_key.pem"),
        require_auth=False
    )
    
    @anp.interface("/info/test.json", description="Test method")
    def test_method(param: str) -> dict:
        """Test method docstring."""
        return {"result": f"Hello {param}"}
    
    # Check registration
    assert test_method in anp.interface_manager.functions
    assert len(anp.interface_manager.functions) == 1
    
    # Check function name uniqueness
    try:
        @anp.interface("/info/test2.json")
        def test_method(param: str) -> dict:  # Same name!
            return {}
        assert False, "Should have raised ValueError"
    except ValueError as e:
        assert "already registered" in str(e)
        print("✓ Function name uniqueness check works")
    
    print("✓ Interface registration works")


def test_interface_proxy():
    """Test InterfaceProxy access modes."""
    print("\nTesting InterfaceProxy...")
    
    app = FastAPI()
    anp = FastANP(
        app=app,
        name="Test Agent",
        description="Test",
        base_url="https://test.example.com",
        did="did:wba:test.example.com:agent:test",
        did_document_path=str(project_root / "docs" / "did_public" / "public-did-doc.json"),
        private_key_path=str(project_root / "docs" / "jwt_rs256" / "private_key.pem"),
        public_key_path=str(project_root / "docs" / "jwt_rs256" / "public_key.pem"),
        require_auth=False
    )
    
    @anp.interface("/info/my_method.json", description="My method")
    def my_method(param: str) -> dict:
        return {"result": param}
    
    # Access via interfaces dict
    proxy = anp.interfaces[my_method]
    
    # Test link_summary
    link = proxy.link_summary
    assert link["type"] == "StructuredInterface"
    assert link["protocol"] == "openrpc"
    assert link["url"] == "https://test.example.com/info/my_method.json"
    print("✓ link_summary works")
    
    # Test content
    content = proxy.content
    assert content["type"] == "StructuredInterface"
    assert content["protocol"] == "openrpc"
    assert "content" in content
    assert content["content"]["openrpc"] == "1.3.2"
    print("✓ content works")
    
    # Test openrpc_doc
    doc = proxy.openrpc_doc
    assert doc["openrpc"] == "1.3.2"
    assert "methods" in doc
    assert len(doc["methods"]) == 1
    assert doc["methods"][0]["name"] == "my_method"
    print("✓ openrpc_doc works")


def test_common_header():
    """Test get_common_header method."""
    print("\nTesting get_common_header...")
    
    app = FastAPI()
    anp = FastANP(
        app=app,
        name="Test Agent",
        description="Test description",
        base_url="https://test.example.com",
        did="did:wba:test.example.com:agent:test",
        did_document_path=str(project_root / "docs" / "did_public" / "public-did-doc.json"),
        private_key_path=str(project_root / "docs" / "jwt_rs256" / "private_key.pem"),
        public_key_path=str(project_root / "docs" / "jwt_rs256" / "public_key.pem"),
        require_auth=False,
        owner={"type": "Person", "name": "Test Owner"}
    )
    
    header = anp.get_common_header()
    
    assert header["protocolType"] == "ANP"
    assert header["protocolVersion"] == "1.0.0"
    assert header["type"] == "AgentDescription"
    assert header["name"] == "Test Agent"
    assert header["did"] == "did:wba:test.example.com:agent:test"
    assert header["description"] == "Test description"
    assert "created" in header
    assert header["owner"]["name"] == "Test Owner"
    print("✓ get_common_header works")


def test_json_rpc_endpoint():
    """Test JSON-RPC endpoint functionality."""
    print("\nTesting JSON-RPC endpoint...")
    
    app = FastAPI()
    anp = FastANP(
        app=app,
        name="Test Agent",
        description="Test",
        base_url="https://test.example.com",
        did="did:wba:test.example.com:agent:test",
        did_document_path=str(project_root / "docs" / "did_public" / "public-did-doc.json"),
        private_key_path=str(project_root / "docs" / "jwt_rs256" / "private_key.pem"),
        public_key_path=str(project_root / "docs" / "jwt_rs256" / "public_key.pem"),
        require_auth=False
    )
    
    @anp.interface("/info/add.json")
    def add(a: int, b: int) -> dict:
        return {"result": a + b}
    
    client = TestClient(app)
    
    # Test successful call
    response = client.post("/rpc", json={
        "jsonrpc": "2.0",
        "id": 1,
        "method": "add",
        "params": {"a": 5, "b": 3}
    })
    assert response.status_code == 200
    data = response.json()
    assert data["jsonrpc"] == "2.0"
    assert data["id"] == 1
    assert data["result"]["result"] == 8
    print("✓ JSON-RPC successful call works")
    
    # Test method not found
    response = client.post("/rpc", json={
        "jsonrpc": "2.0",
        "id": 2,
        "method": "unknown",
        "params": {}
    })
    data = response.json()
    assert "error" in data
    assert data["error"]["code"] == -32601
    print("✓ JSON-RPC method not found error works")
    
    # Test invalid params
    response = client.post("/rpc", json={
        "jsonrpc": "2.0",
        "id": 3,
        "method": "add",
        "params": {"a": 5}  # Missing 'b'
    })
    data = response.json()
    assert "error" in data
    assert data["error"]["code"] == -32602
    print("✓ JSON-RPC invalid params error works")


def test_context_injection():
    """Test Context automatic injection."""
    print("\nTesting Context injection...")
    
    app = FastAPI()
    anp = FastANP(
        app=app,
        name="Test Agent",
        description="Test",
        base_url="https://test.example.com",
        did="did:wba:test.example.com:agent:test",
        did_document_path=str(project_root / "docs" / "did_public" / "public-did-doc.json"),
        private_key_path=str(project_root / "docs" / "jwt_rs256" / "private_key.pem"),
        public_key_path=str(project_root / "docs" / "jwt_rs256" / "public_key.pem"),
        require_auth=False
    )
    
    @anp.interface("/info/with_context.json")
    def with_context(message: str, ctx: Context) -> dict:
        # Access session
        count = ctx.session.get("count", 0) + 1
        ctx.session.set("count", count)
        
        return {
            "message": message,
            "session_id": ctx.session.id,
            "did": ctx.did,
            "count": count
        }
    
    client = TestClient(app)
    
    # First call
    response = client.post("/rpc", json={
        "jsonrpc": "2.0",
        "id": 1,
        "method": "with_context",
        "params": {"message": "Hello"}
    })
    assert response.status_code == 200
    data1 = response.json()
    assert data1["result"]["count"] == 1
    assert "session_id" in data1["result"]
    print("✓ Context injection works")
    
    # Second call (same anonymous session)
    response = client.post("/rpc", json={
        "jsonrpc": "2.0",
        "id": 2,
        "method": "with_context",
        "params": {"message": "World"}
    })
    data2 = response.json()
    # In anonymous mode, all requests share the same session
    assert data2["result"]["session_id"] == data1["result"]["session_id"]
    assert data2["result"]["count"] == 2  # Count increases
    print("✓ Session management works")


def test_pydantic_models():
    """Test Pydantic model support."""
    print("\nTesting Pydantic model support...")
    
    app = FastAPI()
    anp = FastANP(
        app=app,
        name="Test Agent",
        description="Test",
        base_url="https://test.example.com",
        did="did:wba:test.example.com:agent:test",
        did_document_path=str(project_root / "docs" / "did_public" / "public-did-doc.json"),
        private_key_path=str(project_root / "docs" / "jwt_rs256" / "private_key.pem"),
        public_key_path=str(project_root / "docs" / "jwt_rs256" / "public_key.pem"),
        require_auth=False
    )
    
    class CalculateRequest(BaseModel):
        a: int
        b: int
        operation: str
    
    @anp.interface("/info/calculate.json")
    def calculate(request: CalculateRequest) -> dict:
        if request.operation == "add":
            result = request.a + request.b
        else:
            result = request.a * request.b
        return {"result": result}
    
    client = TestClient(app)
    
    response = client.post("/rpc", json={
        "jsonrpc": "2.0",
        "id": 1,
        "method": "calculate",
        "params": {
            "request": {
                "a": 10,
                "b": 5,
                "operation": "add"
            }
        }
    })
    assert response.status_code == 200
    data = response.json()
    assert data["result"]["result"] == 15
    print("✓ Pydantic model support works")


def test_openrpc_document_endpoint():
    """Test OpenRPC document endpoint."""
    print("\nTesting OpenRPC document endpoint...")
    
    app = FastAPI()
    anp = FastANP(
        app=app,
        name="Test Agent",
        description="Test",
        base_url="https://test.example.com",
        did="did:wba:test.example.com:agent:test",
        did_document_path=str(project_root / "docs" / "did_public" / "public-did-doc.json"),
        private_key_path=str(project_root / "docs" / "jwt_rs256" / "private_key.pem"),
        public_key_path=str(project_root / "docs" / "jwt_rs256" / "public_key.pem"),
        require_auth=False
    )
    
    @anp.interface("/info/test_method.json")
    def test_method(param: str) -> dict:
        return {"result": param}
    
    client = TestClient(app)
    
    # Test GET endpoint for OpenRPC doc
    response = client.get("/info/test_method.json")
    assert response.status_code == 200
    doc = response.json()
    assert doc["openrpc"] == "1.3.2"
    assert len(doc["methods"]) == 1
    assert doc["methods"][0]["name"] == "test_method"
    print("✓ OpenRPC document endpoint works")


def main():
    """Run all integration tests."""
    print("=" * 60)
    print("FastANP Integration Tests")
    print("=" * 60)
    
    try:
        test_basic_setup()
        test_interface_registration()
        test_interface_proxy()
        test_common_header()
        test_json_rpc_endpoint()
        test_context_injection()
        test_pydantic_models()
        test_openrpc_document_endpoint()
        
        print("\n" + "=" * 60)
        print("✓ All integration tests passed!")
        print("=" * 60)
        return 0
    
    except AssertionError as e:
        print(f"\n✗ Test failed: {e}")
        import traceback
        traceback.print_exc()
        return 1
    except Exception as e:
        print(f"\n✗ Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())

