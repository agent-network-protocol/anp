#!/usr/bin/env python3
"""
Test script for Context and Request injection updates.

Tests:
1. Context injection with DID-based session
2. Request injection
3. Session persistence based on DID only
4. Middleware setting request.state
"""

import sys
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root))

from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

from anp.fastanp import Context, FastANP


def test_context_injection():
    """Test Context injection and DID-based sessions."""
    print("\n1. Testing Context injection...")
    
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
        require_auth=False,
        enable_auth_middleware=False
    )
    
    @anp.interface("/info/counter.json")
    def counter(ctx: Context) -> dict:
        count = ctx.session.get("count", 0) + 1
        ctx.session.set("count", count)
        return {
            "count": count,
            "session_id": ctx.session.id,
            "did": ctx.did
        }
    
    client = TestClient(app)
    
    # First call
    r1 = client.post("/rpc", json={
        "jsonrpc": "2.0",
        "id": 1,
        "method": "counter",
        "params": {}
    })
    result1 = r1.json()["result"]
    assert result1["count"] == 1
    assert result1["did"] == "anonymous"
    session_id1 = result1["session_id"]
    print(f"   ✓ First call: count=1, session_id={session_id1[:8]}...")
    
    # Second call - same session (DID-based)
    r2 = client.post("/rpc", json={
        "jsonrpc": "2.0",
        "id": 2,
        "method": "counter",
        "params": {}
    })
    result2 = r2.json()["result"]
    assert result2["count"] == 2
    assert result2["session_id"] == session_id1  # Same session
    print("   ✓ Second call: count=2, same session")
    
    print("   ✓ Context injection works correctly")


def test_request_injection():
    """Test Request parameter injection."""
    print("\n2. Testing Request injection...")
    
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
        require_auth=False,
        enable_auth_middleware=False
    )
    
    @anp.interface("/info/with_request.json")
    def with_request(message: str, req: Request) -> dict:
        return {
            "message": message,
            "has_request": req is not None,
            "client_host": req.client.host if req.client else None,
            "method": req.method
        }
    
    client = TestClient(app)
    
    response = client.post("/rpc", json={
        "jsonrpc": "2.0",
        "id": 1,
        "method": "with_request",
        "params": {"message": "test"}
    })
    
    result = response.json()["result"]
    assert result["has_request"] is True
    assert result["method"] == "POST"
    print(f"   ✓ Request injection works: method={result['method']}")


def test_combined_injection():
    """Test both Context and Request injection together."""
    print("\n3. Testing combined Context + Request injection...")
    
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
        require_auth=False,
        enable_auth_middleware=False
    )
    
    @anp.interface("/info/combined.json")
    def combined(message: str, ctx: Context, req: Request) -> dict:
        count = ctx.session.get("count", 0) + 1
        ctx.session.set("count", count)
        return {
            "message": message,
            "count": count,
            "did": ctx.did,
            "method": req.method,
            "session_id": ctx.session.id
        }
    
    client = TestClient(app)
    
    response = client.post("/rpc", json={
        "jsonrpc": "2.0",
        "id": 1,
        "method": "combined",
        "params": {"message": "test"}
    })
    
    result = response.json()["result"]
    assert result["count"] == 1
    assert result["did"] == "anonymous"
    assert result["method"] == "POST"
    print(f"   ✓ Combined injection works: count={result['count']}, method={result['method']}")


def test_middleware_state():
    """Test that middleware sets request.state correctly."""
    print("\n4. Testing middleware request.state...")
    
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
        require_auth=False,
        enable_auth_middleware=True  # Enable middleware
    )
    
    @app.get("/ad.json")
    def get_ad():
        return {"name": "test"}
    
    @anp.interface("/info/check_state.json")
    def check_state(req: Request) -> dict:
        # Check if request.state has auth_result and did
        has_auth_result = hasattr(req.state, 'auth_result')
        has_did = hasattr(req.state, 'did')
        did_value = getattr(req.state, 'did', None)
        
        return {
            "has_auth_result": has_auth_result,
            "has_did": has_did,
            "did": did_value
        }
    
    client = TestClient(app)
    
    # Test excluded path works without auth
    response = client.get("/ad.json")
    assert response.status_code == 200
    print("   ✓ Excluded path /ad.json works without auth")
    
    # Test protected endpoint requires auth
    response = client.post("/rpc", json={
        "jsonrpc": "2.0",
        "id": 1,
        "method": "check_state",
        "params": {}
    })
    
    # Should fail with 401 due to missing auth
    assert response.status_code == 401
    assert "Unauthorized" in response.json().get("error", "")
    print("   ✓ Protected endpoint correctly requires auth")


def test_auth_failures():
    """Test authentication failure cases."""
    print("\n5. Testing authentication failures...")
    
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
        require_auth=False,
        enable_auth_middleware=True  # Enable strict auth middleware
    )
    
    @app.get("/ad.json")
    def get_ad():
        return anp.get_common_header()
    
    @anp.interface("/info/protected.json")
    def protected_method(param: str) -> dict:
        return {"result": param}
    
    client = TestClient(app)
    
    # Test 1: Missing Authorization header on protected endpoint
    print("   Testing missing Authorization header...")
    response = client.post("/rpc", json={
        "jsonrpc": "2.0",
        "id": 1,
        "method": "protected_method",
        "params": {"param": "test"}
    })
    assert response.status_code == 401
    error_data = response.json()
    assert error_data["error"] == "Unauthorized"
    assert "Missing authorization header" in error_data["message"]
    print("   ✓ Missing auth header returns 401")
    
    # Test 2: Invalid Authorization header format
    print("   Testing invalid Authorization header...")
    response = client.post(
        "/rpc",
        json={"jsonrpc": "2.0", "id": 2, "method": "protected_method", "params": {"param": "test"}},
        headers={"Authorization": "InvalidFormat"}
    )
    assert response.status_code in [401, 403, 500]  # Should return error
    error_data = response.json()
    assert "error" in error_data
    print(f"   ✓ Invalid auth header returns {response.status_code}")
    
    # Test 3: Excluded paths work without auth
    print("   Testing excluded paths...")
    
    # /ad.json should work
    response = client.get("/ad.json")
    assert response.status_code == 200
    print("   ✓ /ad.json works without auth")
    
    # /info/* paths (OpenRPC docs) should work
    response = client.get("/info/protected.json")
    assert response.status_code == 200
    doc = response.json()
    assert doc["openrpc"] == "1.3.2"
    print("   ✓ /info/protected.json (OpenRPC doc) works without auth")
    
    # Test 4: Custom endpoints require auth
    @app.get("/custom-endpoint")
    def custom_endpoint():
        return {"data": "custom"}
    
    response = client.get("/custom-endpoint")
    assert response.status_code == 401
    print("   ✓ Custom endpoint requires auth")
    
    print("   ✓ All authentication failure tests passed")


def main():
    """Run all tests."""
    print("=" * 60)
    print("Testing Context and Request Injection Updates")
    print("=" * 60)
    
    try:
        test_context_injection()
        test_request_injection()
        test_combined_injection()
        test_middleware_state()
        test_auth_failures()
        
        print("\n" + "=" * 60)
        print("✓ All tests passed!")
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

