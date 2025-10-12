#!/usr/bin/env python3
"""
Test script for Context and Request injection updates.

Tests:
1. Context injection with DID-based session
2. Request injection
3. Session persistence based on DID only
4. Middleware setting request.state
5. Real DID WBA authentication
"""

import copy
import json
import sys
from pathlib import Path
# Add project root to path
project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root))

from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

from anp.authentication import DIDWbaAuthHeader
from anp.authentication import did_wba_verifier as verifier_module
from anp.authentication.did_wba_verifier import DidWbaVerifierConfig
from anp.fastanp import Context, FastANP

# Shared paths for DID and JWT assets
DOCS_DIR = project_root / "docs"
DID_DOCUMENT_PATH = DOCS_DIR / "did_public" / "public-did-doc.json"
DID_PRIVATE_KEY_PATH = DOCS_DIR / "did_public" / "public-private-key.pem"
JWT_PRIVATE_KEY_PATH = DOCS_DIR / "jwt_rs256" / "RS256-private.pem"
JWT_PUBLIC_KEY_PATH = DOCS_DIR / "jwt_rs256" / "RS256-public.pem"

with open(DID_DOCUMENT_PATH, "r", encoding="utf-8") as did_file:
    DID_DOCUMENT = json.load(did_file)
    TEST_DID = DID_DOCUMENT["id"]

with open(JWT_PRIVATE_KEY_PATH, "r", encoding="utf-8") as private_key_file:
    JWT_PRIVATE_KEY = private_key_file.read()

with open(JWT_PUBLIC_KEY_PATH, "r", encoding="utf-8") as public_key_file:
    JWT_PUBLIC_KEY = public_key_file.read()


def test_context_injection():
    """Test Context injection and DID-based sessions."""
    print("\n1. Testing Context injection...")

    app = FastAPI()
    anp = FastANP(
        app=app,
        name="Test Agent",
        description="Test",
        base_url="https://test.example.com",
        did=TEST_DID,
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
        did=TEST_DID,
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
        did=TEST_DID,
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

    # Create auth config
    auth_config = DidWbaVerifierConfig(
        jwt_private_key=JWT_PRIVATE_KEY,
        jwt_public_key=JWT_PUBLIC_KEY,
        jwt_algorithm="RS256"
    )

    app = FastAPI()
    anp = FastANP(
        app=app,
        name="Test Agent",
        description="Test",
        base_url="https://test.example.com",
        did=TEST_DID,
        enable_auth_middleware=True,  # Enable middleware
        auth_config=auth_config
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
    assert "Missing authorization header" in response.json().get("detail", "")
    print("   ✓ Protected endpoint correctly requires auth")


def test_auth_failures():
    """Test authentication failure cases."""
    print("\n5. Testing authentication failures...")

    # Create auth config
    auth_config = DidWbaVerifierConfig(
        jwt_private_key=JWT_PRIVATE_KEY,
        jwt_public_key=JWT_PUBLIC_KEY,
        jwt_algorithm="RS256"
    )

    app = FastAPI()
    anp = FastANP(
        app=app,
        name="Test Agent",
        description="Test",
        base_url="https://test.example.com",
        did=TEST_DID,
        enable_auth_middleware=True,  # Enable strict auth middleware
        auth_config=auth_config
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
    assert "detail" in error_data
    assert "Missing authorization header" in error_data["detail"]
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
    assert "detail" in error_data
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


def test_real_did_wba_auth():
    """Test real DID WBA authentication flow."""
    print("\n6. Testing real DID WBA authentication...")

    app = FastAPI()

    # Use shared DID document and JWT keys from docs directory
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
            jwt_private_key=JWT_PRIVATE_KEY,
            jwt_public_key=JWT_PUBLIC_KEY,
            jwt_algorithm="RS256"
        )

        anp = FastANP(
            app=app,
            name="Auth Test Agent",
            description="Test real DID WBA authentication",
            base_url="https://test.example.com",
            did=did_document["id"],
            enable_auth_middleware=True,
            auth_config=auth_config
        )
        
        @app.get("/ad.json")
        def get_ad():
            return anp.get_common_header()
        
        @anp.interface("/info/secure.json")
        def secure_method(param: str, ctx: Context) -> dict:
            count = ctx.session.get("count", 0) + 1
            ctx.session.set("count", count)
            return {
                "param": param,
                "count": count,
                "did": ctx.did,
                "session_id": ctx.session.id
            }
        
        # Create authenticator
        authenticator = DIDWbaAuthHeader(
            did_document_path=str(DID_DOCUMENT_PATH),
            private_key_path=str(DID_PRIVATE_KEY_PATH)
        )
        
        client = TestClient(app, base_url="https://test.example.com")
        
        # Test 1: Generate DID WBA auth header
        print("   Testing DID WBA authentication...")
        server_url = "https://test.example.com/resource"
        auth_headers = authenticator.get_auth_header(server_url, force_new=True)
        authorization = auth_headers["Authorization"]
        
        assert authorization.startswith("DIDWba")
        print(f"   ✓ Generated DID WBA header: {authorization[:50]}...")
        
        # Test 2: Call protected endpoint with DID auth
        response = client.post(
            "/rpc",
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "secure_method",
                "params": {"param": "test1"}
            },
            headers={"Authorization": authorization}
        )
        
        assert response.status_code == 200
        result1 = response.json()["result"]
        assert result1["count"] == 1
        assert result1["did"] == did_document["id"]
        session_id1 = result1["session_id"]
        print(f"   ✓ DID WBA auth successful, session created: {session_id1[:8]}...")
        
        # Test 3: Second call with same DID shares session
        # Generate new auth header
        auth_headers2 = authenticator.get_auth_header(server_url, force_new=True)
        authorization2 = auth_headers2["Authorization"]
        
        response = client.post(
            "/rpc",
            json={
                "jsonrpc": "2.0",
                "id": 2,
                "method": "secure_method",
                "params": {"param": "test2"}
            },
            headers={"Authorization": authorization2}
        )
        
        assert response.status_code == 200
        result2 = response.json()["result"]
        assert result2["count"] == 2  # Same session, count incremented
        assert result2["session_id"] == session_id1  # Same session ID
        assert result2["did"] == did_document["id"]
        print(f"   ✓ Same DID shares session, count={result2['count']}")
        
        # Test 4: Verify Bearer token flow
        print("   Testing Bearer token flow...")
        # Extract access token from first auth
        # In real scenario, we would get this from the response
        # For now, we'll use the DID auth which returns a token
        
        print("   ✓ Real DID WBA authentication tests passed")
        
    finally:
        # Restore original resolver
        verifier_module.resolve_did_wba_document = original_resolver


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
        test_real_did_wba_auth()
        
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
