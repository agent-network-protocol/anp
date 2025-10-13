#!/usr/bin/env python3
"""
测试 agent_domain 规范化功能

测试各种输入格式：
- www.a.com
- a.com
- http://0.0.0.0:80
- https://a.com
- localhost:8000
- 127.0.0.1:8000
"""

import sys
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root))

from anp.fastanp.utils import normalize_agent_domain


def test_normalize_agent_domain():
    """测试 agent_domain 规范化功能"""

    test_cases = [
        # (输入, 期望的完整URL, 期望的纯域名)
        ("www.a.com", "https://www.a.com", "www.a.com"),
        ("a.com", "https://a.com", "a.com"),
        ("http://0.0.0.0:80", "http://0.0.0.0:80", "0.0.0.0:80"),
        ("https://a.com", "https://a.com", "a.com"),
        ("localhost:8000", "http://localhost:8000", "localhost:8000"),
        ("127.0.0.1:8000", "http://127.0.0.1:8000", "127.0.0.1:8000"),
        ("0.0.0.0:8000", "http://0.0.0.0:8000", "0.0.0.0:8000"),
        ("https://example.com:443", "https://example.com:443", "example.com:443"),
        ("http://example.com:8080", "http://example.com:8080", "example.com:8080"),
        ("localhost", "http://localhost", "localhost"),
        ("https://www.example.com", "https://www.example.com", "www.example.com"),
        ("example.com:3000", "https://example.com:3000", "example.com:3000"),
    ]

    print("=" * 80)
    print("测试 agent_domain 规范化功能")
    print("=" * 80)

    passed = 0
    failed = 0

    for input_domain, expected_url, expected_domain in test_cases:
        try:
            actual_url, actual_domain = normalize_agent_domain(input_domain)

            if actual_url == expected_url and actual_domain == expected_domain:
                print(f"✓ PASS: '{input_domain}'")
                print(f"  → URL: {actual_url}")
                print(f"  → Domain: {actual_domain}")
                passed += 1
            else:
                print(f"✗ FAIL: '{input_domain}'")
                print(f"  期望 URL: {expected_url}, 实际: {actual_url}")
                print(f"  期望 Domain: {expected_domain}, 实际: {actual_domain}")
                failed += 1
        except Exception as e:
            print(f"✗ ERROR: '{input_domain}' - {e}")
            failed += 1
        print()

    print("=" * 80)
    print(f"测试结果: {passed} 通过, {failed} 失败")
    print("=" * 80)

    return failed == 0


def test_fastanp_integration():
    """测试 FastANP 集成"""
    from fastapi import FastAPI
    from anp.fastanp import FastANP

    print("\n" + "=" * 80)
    print("测试 FastANP 集成")
    print("=" * 80)

    test_cases = [
        "localhost:8000",
        "example.com",
        "https://api.example.com",
        "http://0.0.0.0:5000",
    ]

    for agent_domain_input in test_cases:
        try:
            app = FastAPI()
            anp = FastANP(
                app=app,
                name="Test Agent",
                description="Test",
                agent_domain=agent_domain_input,
                agent_description_path="/ad.json",
                did="did:wba:test.com:agent:test",
                enable_auth_middleware=False
            )

            print(f"✓ PASS: '{agent_domain_input}'")
            print(f"  → agent_domain: {anp.agent_domain}")
            print(f"  → domain: {anp.domain}")
            print(f"  → base_url: {anp.base_url}")

            # 测试 ad.json URL 生成
            ad = anp.get_common_header()
            print(f"  → ad.json URL: {ad['url']}")
            print()

        except Exception as e:
            print(f"✗ ERROR: '{agent_domain_input}' - {e}")
            import traceback
            traceback.print_exc()
            print()

    print("=" * 80)


def main():
    """运行所有测试"""
    success = test_normalize_agent_domain()
    test_fastanp_integration()

    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
