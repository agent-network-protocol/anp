"""OpenANP + ANPCrawler 集成示例

验证 anp_crawler 模块能够连接到 openanp server 并调用接口。

运行方式:
    uv run python anp/unittest/openanp/example_openanp_with_crawler.py
"""

import asyncio
import json
from pathlib import Path

import httpx
import uvicorn
from fastapi import FastAPI

from anp.anp_crawler.anp_crawler import ANPCrawler
from anp.openanp import AgentConfig, Context, anp_agent, interface

# 项目根目录
PROJECT_ROOT = Path(__file__).parent.parent.parent.parent


# =============================================================================
# 1. 定义 OpenANP Agent
# =============================================================================
@anp_agent(
    AgentConfig(
        name="Demo Agent",
        did="did:wba:localhost:demo",
        description="A demo agent for testing anp_crawler integration",
        prefix="/demo",
    )
)
class DemoAgent:
    """演示用 Agent，提供简单的搜索和计算接口。"""

    @interface
    async def search(self, query: str) -> dict:
        """搜索接口。"""
        return {"results": [f"Result for: {query}"], "count": 1}

    @interface
    async def add(self, a: int, b: int) -> dict:
        """加法计算接口。"""
        return {"result": a + b}

    @interface
    async def greet(self, name: str, ctx: Context) -> dict:
        """带 Context 的问候接口。"""
        return {"message": f"Hello, {name}!", "caller_did": ctx.did or "anonymous"}


# =============================================================================
# 2. 创建 FastAPI 应用
# =============================================================================
def create_app() -> FastAPI:
    """创建 FastAPI 应用。"""
    app = FastAPI(title="Demo ANP Server")
    app.include_router(DemoAgent.router())
    return app


# =============================================================================
# 3. 使用 ANPCrawler 测试连接
# =============================================================================
async def test_crawler_connection(base_url: str):
    """使用 ANPCrawler 测试连接到 OpenANP server。"""
    print("\n" + "=" * 60)
    print("ANPCrawler 连接测试")
    print("=" * 60)

    # 初始化 crawler
    crawler = ANPCrawler(
        did_document_path=str(PROJECT_ROOT / "docs" / "did_public" / "public-did-doc.json"),
        private_key_path=str(PROJECT_ROOT / "docs" / "did_public" / "public-private-key.pem"),
    )

    ad_url = f"{base_url}/demo/ad.json"
    print(f"\n[1] 获取 Agent Description: {ad_url}")

    # 获取 agent description
    content_json, interfaces_list = await crawler.fetch_text(ad_url)

    # 打印 ad.json 内容
    print("\nAgent Description 内容:")
    try:
        parsed = json.loads(content_json["content"])
        print(json.dumps(parsed, indent=2, ensure_ascii=False))

        # 检查是否有 URL 引用的接口（而不是内嵌内容）
        # ANPCrawler 需要单独获取这些 URL
        if "interfaces" in parsed:
            for iface in parsed["interfaces"]:
                if iface.get("url") and iface.get("protocol") == "openrpc":
                    interface_url = iface["url"]
                    print(f"\n[2] 获取接口文档: {interface_url}")
                    _, interface_list = await crawler.fetch_text(interface_url)
                    print(f"  从接口文档发现 {len(interface_list)} 个方法")
                    for method in interface_list:
                        print(f"    - {method.get('function', {}).get('name', 'unknown')}")

    except Exception as e:
        print(f"  解析失败: {e}")
        print(content_json["content"])

    # 显示可用工具
    tools = crawler.list_available_tools()
    print(f"\n[3] 可用工具: {tools}")

    # 调用工具
    if "search" in tools:
        print("\n[4] 调用 search 工具")
        result = await crawler.execute_tool_call("search", {"query": "test"})
        print(f"  结果: {json.dumps(result, ensure_ascii=False)}")

    if "add" in tools:
        print("\n[5] 调用 add 工具")
        result = await crawler.execute_tool_call("add", {"a": 10, "b": 20})
        print(f"  结果: {json.dumps(result, ensure_ascii=False)}")

    if "greet" in tools:
        print("\n[6] 调用 greet 工具")
        result = await crawler.execute_tool_call("greet", {"name": "World"})
        print(f"  结果: {json.dumps(result, ensure_ascii=False)}")

    print("\n[7] 会话信息:")
    print(f"  访问的 URL: {crawler.get_visited_urls()}")
    print(f"  缓存条目数: {crawler.get_cache_size()}")

    print("\n" + "=" * 60)
    print("测试完成!")
    print("=" * 60)


# =============================================================================
# 4. 直接使用 httpx 测试（不使用 crawler）
# =============================================================================
async def test_direct_connection(base_url: str):
    """直接使用 httpx 测试 OpenANP server。"""
    print("\n" + "=" * 60)
    print("直接 HTTP 连接测试")
    print("=" * 60)

    # 禁用代理，因为我们测试的是本地服务
    async with httpx.AsyncClient(proxy=None) as client:
        # 测试 ad.json
        print(f"\n[1] GET {base_url}/demo/ad.json")
        resp = await client.get(f"{base_url}/demo/ad.json")
        print(f"  状态码: {resp.status_code}")
        if resp.status_code == 200:
            print(f"  内容: {json.dumps(resp.json(), indent=2, ensure_ascii=False)}")

        # 测试 interface.json
        print(f"\n[2] GET {base_url}/demo/interface.json")
        resp = await client.get(f"{base_url}/demo/interface.json")
        print(f"  状态码: {resp.status_code}")
        if resp.status_code == 200:
            data = resp.json()
            print(f"  OpenRPC 版本: {data.get('openrpc')}")
            print(f"  方法数量: {len(data.get('methods', []))}")
            for m in data.get("methods", []):
                print(f"    - {m.get('name')}: {m.get('description', '')[:50]}")

        # 测试 RPC 调用
        print(f"\n[3] POST {base_url}/demo/rpc (search)")
        rpc_request = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "search",
            "params": {"query": "hello"},
        }
        resp = await client.post(f"{base_url}/demo/rpc", json=rpc_request)
        print(f"  状态码: {resp.status_code}")
        print(f"  响应: {json.dumps(resp.json(), ensure_ascii=False)}")

        # 测试 add
        print(f"\n[4] POST {base_url}/demo/rpc (add)")
        rpc_request = {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "add",
            "params": {"a": 5, "b": 3},
        }
        resp = await client.post(f"{base_url}/demo/rpc", json=rpc_request)
        print(f"  状态码: {resp.status_code}")
        print(f"  响应: {json.dumps(resp.json(), ensure_ascii=False)}")


# =============================================================================
# 5. 主函数
# =============================================================================
async def run_server_and_test():
    """启动服务器并运行测试。"""
    app = create_app()
    host = "127.0.0.1"
    port = 18765

    # 配置 uvicorn
    config = uvicorn.Config(app, host=host, port=port, log_level="warning")
    server = uvicorn.Server(config)

    # 在后台启动服务器
    server_task = asyncio.create_task(server.serve())

    # 等待服务器启动
    await asyncio.sleep(0.5)

    base_url = f"http://{host}:{port}"
    print(f"服务器已启动: {base_url}")

    try:
        # 运行直接连接测试
        await test_direct_connection(base_url)

        # 运行 crawler 测试
        await test_crawler_connection(base_url)

    finally:
        # 关闭服务器
        server.should_exit = True
        await server_task


if __name__ == "__main__":
    asyncio.run(run_server_and_test())
