#!/usr/bin/env python3
"""
Hotel Booking Agent 测试客户端

测试 hotel_booking_agent.py 提供的所有路由和 JSON-RPC 接口
使用 DID WBA 认证进行测试
"""

import json
import sys
from pathlib import Path

import requests

# 添加项目根目录到 Python 路径
project_root = Path(__file__).parent.parent.parent.parent
sys.path.insert(0, str(project_root))

from anp.authentication import DIDWbaAuthHeader
from anp.authentication import did_wba_verifier as verifier_module

# ANSI 颜色代码
GREEN = '\033[92m'
RED = '\033[91m'
YELLOW = '\033[93m'
CYAN = '\033[96m'
BOLD = '\033[1m'
RESET = '\033[0m'


class TestReporter:
    """测试结果报告器，负责编号、输出和统计汇总。"""

    def __init__(self):
        self._counter = 0
        self._results = []

    def success(self, message: str):
        """记录并输出成功结果。"""
        self._counter += 1
        record = {"index": self._counter, "status": "PASS", "message": message}
        self._results.append(record)
        print(f"{GREEN}{BOLD}[{record['index']:03d}] PASS{RESET} {message}")

    def failure(self, message: str):
        """记录并输出失败结果。"""
        self._counter += 1
        record = {"index": self._counter, "status": "FAIL", "message": message}
        self._results.append(record)
        print(f"{RED}{BOLD}[{record['index']:03d}] FAIL{RESET} {message}")

    def summary(self):
        """打印测试结果汇总。"""
        total = len(self._results)
        success_count = sum(1 for r in self._results if r["status"] == "PASS")
        failure_records = [r for r in self._results if r["status"] == "FAIL"]
        failure_count = len(failure_records)

        print(f"\n{CYAN}{BOLD}=== 测试汇总 ==={RESET}")
        print(f"{YELLOW}  总计: {total}, 成功: {success_count}, 失败: {failure_count}{RESET}")
        if failure_records:
            print(f"{RED}{BOLD}  失败详情:{RESET}")
            for record in failure_records:
                print(f"    [{record['index']:03d}] {record['message']}")
        else:
            print(f"{GREEN}  所有测试均通过。{RESET}")


class HotelBookingClient:
    """酒店预订代理测试客户端"""

    def __init__(self, base_url: str = "http://localhost:8000", use_auth: bool = True):
        """
        初始化客户端

        Args:
            base_url: 服务器基础 URL
            use_auth: 是否使用认证
        """
        self.base_url = base_url.rstrip('/')
        self.session = requests.Session()
        self.use_auth = use_auth
        self.reporter = TestReporter()

        # 加载 DID 文档和密钥
        self.did_document_path = project_root / "docs" / "did_public" / "public-did-doc.json"
        self.private_key_path = project_root / "docs" / "did_public" / "public-private-key.pem"

        # 初始化认证器
        if use_auth:
            self.authenticator = DIDWbaAuthHeader(
                did_document_path=str(self.did_document_path),
                private_key_path=str(self.private_key_path)
            )
            
            # Setup local DID resolver for testing
            with open(self.did_document_path, 'r') as f:
                self.did_document = json.load(f)
            
            async def local_resolver(did: str):
                if did != self.did_document["id"]:
                    raise ValueError(f"Unsupported DID: {did}")
                return self.did_document
            
            self.original_resolver = verifier_module.resolve_did_wba_document
            verifier_module.resolve_did_wba_document = local_resolver
        else:
            self.authenticator = None

    def close(self):
        """关闭客户端"""
        if self.use_auth and hasattr(self, 'original_resolver'):
            # Restore original resolver
            verifier_module.resolve_did_wba_document = self.original_resolver
        self.session.close()

    def _pass(self, message: str):
        """记录成功结果。"""
        self.reporter.success(message)

    def _fail(self, message: str):
        """记录失败结果。"""
        self.reporter.failure(message)
    
    def _get_auth_headers(self, prepared_request: requests.PreparedRequest) -> dict:
        """获取认证 headers"""
        if not self.use_auth or not self.authenticator:
            return {}

        return self.authenticator.get_auth_header(
            prepared_request.url,
            force_new=True,
            method=prepared_request.method,
            headers=dict(prepared_request.headers),
            body=prepared_request.body,
        )

    def _make_request(self, method: str, path: str, with_auth: bool = True, **kwargs) -> requests.Response:
        """
        发送 HTTP 请求

        Args:
            method: HTTP 方法
            path: 请求路径
            with_auth: 是否携带认证 header
            **kwargs: 其他请求参数

        Returns:
            HTTP 响应
        """
        url = f"{self.base_url}{path}"
        if not with_auth or not self.use_auth or not self.authenticator:
            return self.session.request(method, url, **kwargs)

        request = requests.Request(method=method, url=url, **kwargs)
        prepared_request = self.session.prepare_request(request)
        prepared_request.headers.update(self._get_auth_headers(prepared_request))

        send_kwargs = self.session.merge_environment_settings(
            prepared_request.url,
            {},
            None,
            None,
            None,
        )
        return self.session.send(prepared_request, **send_kwargs)

    def test_ad_json_endpoints(self):
        """测试 ad.json 端点"""
        print("\n📋 测试 ad.json 端点...")

        # 测试简单 ad.json
        response = self._make_request("GET", "/ad.json")
        if response.status_code == 200:
            data = response.json()
            self._pass(f"简单 ad.json: {response.status_code}")
            print(f"  名称: {data.get('name')}")
            print(f"  DID: {data.get('did')}")
            print(f"  接口数量: {len(data.get('interfaces', []))}")
        else:
            self._fail(f"简单 ad.json: {response.status_code}")

        # 测试带 agent_id 的 ad.json
        response = self._make_request("GET", "/test-agent/ad.json")
        if response.status_code == 200:
            data = response.json()
            self._pass(f"带 agent_id 的 ad.json: {response.status_code}")
            print(f"  信息项数量: {len(data.get('Infomations', []))}")
        else:
            self._fail(f"带 agent_id 的 ad.json: {response.status_code}")

    def test_information_endpoints(self):
        """测试 Information 端点"""
        print("\n📚 测试 Information 端点...")

        # 测试产品信息
        response = self._make_request("GET", "/products/luxury-rooms.json")
        if response.status_code == 200:
            data = response.json()
            products = data.get('products', [])
            self._pass(f"产品信息: {response.status_code}")
            print(f"  产品数量: {len(products)}")
            for product in products:
                print(f"    - {product.get('name')}: ${product.get('price')}")
        else:
            self._fail(f"产品信息: {response.status_code}")

        # 测试酒店信息
        response = self._make_request("GET", "/info/hotel-basic-info.json")
        if response.status_code == 200:
            data = response.json()
            self._pass(f"酒店信息: {response.status_code}")
            print(f"  酒店名称: {data.get('name')}")
            print(f"  设施数量: {len(data.get('facilities', []))}")
        else:
            self._fail(f"酒店信息: {response.status_code}")

    def test_openrpc_endpoints(self):
        """测试 OpenRPC 文档端点"""
        print("\n📄 测试 OpenRPC 文档端点...")

        # 测试 search_rooms OpenRPC 文档
        response = self._make_request("GET", "/info/search_rooms.json")
        if response.status_code == 200:
            data = response.json()
            self._pass(f"search_rooms OpenRPC: {response.status_code}")
            print(f"  OpenRPC 版本: {data.get('openrpc')}")
            print(f"  方法名称: {data.get('info', {}).get('title')}")
        else:
            self._fail(f"search_rooms OpenRPC: {response.status_code}")

        # 测试 get_rooms OpenRPC 文档
        response = self._make_request("GET", "/info/get_rooms.json")
        if response.status_code == 200:
            data = response.json()
            self._pass(f"get_rooms OpenRPC: {response.status_code}")
            print(f"  方法描述: {data.get('info', {}).get('description')}")
        else:
            self._fail(f"get_rooms OpenRPC: {response.status_code}")

    def test_jsonrpc_endpoint(self):
        """测试 JSON-RPC 端点"""
        print("\n🔧 测试 JSON-RPC 端点...")

        # 测试 search_rooms 方法
        payload = {
            "jsonrpc": "2.0",
            "method": "search_rooms",
            "params": {
                "query": {
                    "check_in_date": "2024-12-01",
                    "check_out_date": "2024-12-05",
                    "guest_count": 2,
                    "room_type": "deluxe"
                }
            },
            "id": 1
        }

        response = self._make_request("POST", "/rpc", json=payload)
        if response.status_code == 200:
            data = response.json()
            if 'result' in data:
                result = data['result']
                self._pass(f"search_rooms RPC: {response.status_code}")
                print(f"  搜索成功: {result.get('success')}")
                print(f"  房间数量: {result.get('total')}")
                for room in result.get('rooms', []):
                    print(f"    - 房间 {room.get('id')}: ${room.get('price')}")
            elif 'error' in data:
                self._fail(f"search_rooms RPC 错误: {data['error']}")
        else:
            self._fail(f"search_rooms RPC: {response.status_code}")

        # 测试 get_rooms 方法（带 Context 注入）
        payload = {
            "jsonrpc": "2.0",
            "method": "get_rooms",
            "params": {
                "query": "deluxe rooms"
            },
            "id": 2
        }

        response = self._make_request("POST", "/rpc", json=payload)
        if response.status_code == 200:
            data = response.json()
            if 'result' in data:
                result = data['result']
                self._pass(f"get_rooms RPC: {response.status_code}")
                print(f"  会话 ID: {result.get('session_id', 'N/A')}")
                print(f"  DID: {result.get('did', 'N/A')}")
                print(f"  访问次数: {result.get('visit_count', 0)}")
                print(f"  房间数量: {len(result.get('rooms', []))}")
            elif 'error' in data:
                self._fail(f"get_rooms RPC 错误: {data['error']}")
        else:
            self._fail(f"get_rooms RPC: {response.status_code}")

    def test_error_cases(self):
        """测试错误情况"""
        print("\n❌ 测试错误情况...")

        # 测试不存在的 RPC 方法
        payload = {
            "jsonrpc": "2.0",
            "method": "nonexistent_method",
            "params": {},
            "id": 3
        }

        response = self._make_request("POST", "/rpc", json=payload, with_auth=self.use_auth)
        if response.status_code == 200:
            data = response.json()
            if 'error' in data:
                self._pass(f"不存在的方法返回预期错误: {data['error'].get('message')}")
            else:
                self._fail("不存在的方法应该返回错误")
        elif response.status_code == 401:
            self._pass("认证失败（符合预期）")
        else:
            self._fail(f"不存在的方法: 意外状态码 {response.status_code}")

        # 测试无效的 JSON-RPC 请求
        payload = {
            "jsonrpc": "2.0",
            "method": "search_rooms",
            "params": {
                "invalid_param": "value"
            },
            "id": 4
        }

        response = self._make_request("POST", "/rpc", json=payload, with_auth=self.use_auth)
        if response.status_code == 200:
            data = response.json()
            if 'error' in data:
                self._pass(f"无效参数返回预期错误: {data['error'].get('message')}")
            else:
                self._fail("无效参数应该返回错误")
        else:
            self._fail(f"无效参数: 意外状态码 {response.status_code}")
    
    def test_authentication(self):
        """测试认证功能"""
        if not self.use_auth:
            print("\n🔒 跳过认证测试（未启用认证）")
            return
        
        print("\n🔒 测试 DID WBA 认证功能...")
        
        # Test 1: Without auth should fail
        print("   测试无认证访问...")
        response = self._make_request("POST", "/rpc", with_auth=False, json={
            "jsonrpc": "2.0",
            "id": 1,
            "method": "search_rooms",
            "params": {"query": {"check_in_date": "2025-01-01", "check_out_date": "2025-01-05", "guest_count": 2, "room_type": "deluxe"}}
        })
        if response.status_code == 401:
            self._pass("无认证访问被拒绝（401）")
        else:
            self._fail(f"预期 401，实际得到 {response.status_code}")
        
        # Test 2: With DID WBA auth should succeed
        print("   测试 DID WBA 认证访问...")
        response = self._make_request("POST", "/rpc", 
            json={
                "jsonrpc": "2.0",
                "id": 2,
                "method": "search_rooms",
                "params": {"query": {"check_in_date": "2025-01-01", "check_out_date": "2025-01-05", "guest_count": 2, "room_type": "deluxe"}}
            },
            with_auth=True
        )
        if response.status_code == 200:
            data = response.json()
            if 'result' in data:
                result = data['result']
                self._pass(f"认证成功，返回 {result.get('total', 0)} 个房间")
            else:
                self._fail("认证成功但响应格式错误")
        else:
            self._fail(f"认证失败: {response.status_code}")
            print(f"   响应: {response.text}")
        
        # Test 3: Test session persistence with auth
        print("   测试认证会话持久化...")
        response1 = self._make_request("POST", "/rpc",
            json={
                "jsonrpc": "2.0",
                "id": 3,
                "method": "get_rooms",
                "params": {"query": "suite"}
            },
            with_auth=True
        )
        
        if response1.status_code == 200:
            result1 = response1.json()['result']
            visit_count1 = result1.get('visit_count', 0)
            session_id1 = result1.get('session_id', '')
            print(f"   第一次调用: visit_count={visit_count1}, session={session_id1[:8] if session_id1 else 'N/A'}...")
            
            # Second call with new auth but same DID
            response2 = self._make_request("POST", "/rpc",
                json={
                    "jsonrpc": "2.0",
                    "id": 4,
                    "method": "get_rooms",
                    "params": {"query": "deluxe"}
                },
                with_auth=True
            )
            
            if response2.status_code == 200:
                result2 = response2.json()['result']
                visit_count2 = result2.get('visit_count', 0)
                session_id2 = result2.get('session_id', '')
                
                if session_id1 == session_id2 and visit_count2 == visit_count1 + 1:
                    self._pass(f"会话持久化成功: visit_count={visit_count2}, 相同 session")
                else:
                    self._fail(f"会话可能未共享: visit_count={visit_count2}")
            else:
                self._fail(f"第二次调用失败: {response2.status_code}")
        else:
            self._fail(f"第一次调用失败: {response1.status_code}")
        
        self._pass("认证功能测试完成")

    def run_all_tests(self):
        """运行所有测试"""
        print("🚀 开始酒店预订代理测试...")
        print(f"目标服务器: {self.base_url}")
        print(f"使用认证: {'是' if self.use_auth else '否'}")
        if self.use_auth:
            print(f"使用 DID 文档: {self.did_document_path}")

        try:
            self.test_ad_json_endpoints()
            self.test_information_endpoints()
            self.test_openrpc_endpoints()
            self.test_authentication()  # Test auth first
            self.test_jsonrpc_endpoint()
            self.test_error_cases()

            print(f"\n{GREEN}🎉 所有测试完成！{RESET}")

        except Exception as e:
            self._fail(f"测试过程中出现未处理异常: {e}")
            print(f"\n{RED}❌ 测试过程中出现错误: {e}{RESET}")
            import traceback
            traceback.print_exc()
        finally:
            self.reporter.summary()


def main():
    """主函数"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Hotel Booking Agent 测试客户端")
    parser.add_argument("--auth", action="store_true", default=True, help="启用 DID WBA 认证测试")
    parser.add_argument("--base-url", default="http://localhost:8000", help="服务器基础 URL")
    args = parser.parse_args()
    
    client = HotelBookingClient(base_url=args.base_url, use_auth=args.auth)

    try:
        client.run_all_tests()
    finally:
        client.close()


if __name__ == "__main__":
    # 运行测试
    # 默认不使用认证（用于本地测试）
    # 使用 --auth 参数启用认证测试
    main()
