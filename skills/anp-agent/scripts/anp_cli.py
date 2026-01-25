#!/usr/bin/env python3
"""
ANP 动态调用工具 - 给 AD URL 就能连

用法：
    # 直接用 AD URL 连接查看能力
    python anp_cli.py connect "https://xxx/ad.json"
    
    # 调用已注册的 Agent
    python anp_cli.py call amap maps_text_search '{"keywords":"咖啡厅","city":"北京"}'
    
    # 添加新 Agent
    python anp_cli.py add myagent "https://example.com/ad.json"
    
    # 列出所有已注册 Agent
    python anp_cli.py list
"""

import asyncio
import json
import sys
from pathlib import Path
from typing import Optional
import aiohttp

from anp.anp_crawler import ANPCrawler

CONFIG_DIR = Path(__file__).parent.parent / "config"
AGENTS_FILE = CONFIG_DIR / "agents.json"

def load_agents():
    if AGENTS_FILE.exists():
        with open(AGENTS_FILE) as f:
            return json.load(f)
    return {"agents": []}

def save_agents(data):
    with open(AGENTS_FILE, "w") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

def get_crawler():
    return ANPCrawler(
        did_document_path=str(CONFIG_DIR / "did.json"),
        private_key_path=str(CONFIG_DIR / "private-key.pem")
    )

async def fetch_ad(ad_url: str) -> dict:
    """获取 AD 文档"""
    async with aiohttp.ClientSession() as session:
        async with session.get(ad_url, timeout=aiohttp.ClientTimeout(total=15)) as resp:
            if resp.status == 200:
                return await resp.json()
            raise Exception(f"获取 AD 失败: HTTP {resp.status}")

async def get_interface(ad: dict) -> tuple:
    """从 AD 获取接口定义和 RPC 端点"""
    interfaces = ad.get("interfaces", [])
    if not interfaces:
        return None, None, []
    
    interface = interfaces[0]
    interface_url = interface.get("url")
    
    rpc_endpoint = None
    methods = []
    
    if interface_url:
        async with aiohttp.ClientSession() as session:
            async with session.get(interface_url, timeout=aiohttp.ClientTimeout(total=15)) as resp:
                if resp.status == 200:
                    interface_doc = await resp.json()
                    servers = interface_doc.get("servers", [])
                    if servers:
                        rpc_endpoint = servers[0].get("url")
                    methods = interface_doc.get("methods", [])
    
    return interface_url, rpc_endpoint, methods

async def connect(ad_url: str, show_methods: bool = True):
    """连接到 Agent，显示其能力"""
    print(f"正在连接: {ad_url}\n")
    
    ad = await fetch_ad(ad_url)
    
    print(f"Agent: {ad.get('name', 'Unknown')}")
    print(f"DID: {ad.get('did', 'N/A')}")
    print(f"描述: {ad.get('description', 'N/A')}")
    
    interface_url, rpc_endpoint, methods = await get_interface(ad)
    
    if rpc_endpoint:
        print(f"RPC 端点: {rpc_endpoint}")
    
    if show_methods and methods:
        print(f"\n可用方法 ({len(methods)} 个):")
        for m in methods[:20]:
            desc = m.get("description", "")[:60]
            print(f"  - {m.get('name')}: {desc}")
        if len(methods) > 20:
            print(f"  ... 还有 {len(methods) - 20} 个方法")
    
    return ad, rpc_endpoint, methods

async def call_method(ad_url_or_id: str, method: str, params: dict):
    """调用 Agent 方法"""
    agents_data = load_agents()
    
    ad_url = ad_url_or_id
    for agent in agents_data.get("agents", []):
        if agent.get("id") == ad_url_or_id:
            ad_url = agent.get("ad_url")
            break
    
    print(f"正在获取 Agent 信息...")
    ad = await fetch_ad(ad_url)
    _, rpc_endpoint, _ = await get_interface(ad)
    
    if not rpc_endpoint:
        print("错误: 无法获取 RPC 端点")
        return
    
    print(f"调用: {method}")
    print(f"端点: {rpc_endpoint}")
    print(f"参数: {params}\n")
    
    crawler = get_crawler()
    result = await crawler.execute_json_rpc(
        endpoint=rpc_endpoint,
        method=method,
        params=params
    )
    
    print("=== 结果 ===")
    print(json.dumps(result, indent=2, ensure_ascii=False))

async def add_agent(agent_id: str, ad_url: str):
    """添加新 Agent 到配置"""
    print(f"正在验证 Agent: {ad_url}")
    
    try:
        ad = await fetch_ad(ad_url)
        name = ad.get("name", agent_id)
        
        agents_data = load_agents()
        
        for agent in agents_data.get("agents", []):
            if agent.get("id") == agent_id:
                agent["ad_url"] = ad_url
                agent["name"] = name
                save_agents(agents_data)
                print(f"✅ 已更新: {agent_id} -> {name}")
                return
        
        agents_data["agents"].append({
            "id": agent_id,
            "name": name,
            "ad_url": ad_url
        })
        save_agents(agents_data)
        print(f"✅ 已添加: {agent_id} -> {name}")
        print(f"   AD: {ad_url}")
        
    except Exception as e:
        print(f"❌ 添加失败: {e}")

def list_agents():
    """列出所有已注册 Agent"""
    agents_data = load_agents()
    agents = agents_data.get("agents", [])
    
    if not agents:
        print("暂无已注册的 Agent")
        print("使用 'python anp_cli.py add <id> <ad_url>' 添加")
        return
    
    print(f"\n已注册的 ANP Agent ({len(agents)} 个):\n")
    for agent in agents:
        print(f"  {agent.get('id')}: {agent.get('name')}")
        print(f"      {agent.get('ad_url')}")
        print()

def show_help():
    print("""
ANP 动态调用工具

用法:
    python anp_cli.py <命令> [参数...]

命令:
    connect <ad_url>                      连接并查看 Agent 能力
    call <id|ad_url> <method> <params>    调用方法
    add <id> <ad_url>                     添加新 Agent
    remove <id>                           移除 Agent
    list                                  列出所有 Agent

示例:
    # 连接查看
    python anp_cli.py connect "https://agent-connect.ai/mcp/agents/amap/ad.json"
    
    # 调用方法 (用已注册的 id)
    python anp_cli.py call amap maps_text_search '{"keywords":"咖啡厅","city":"北京"}'
    
    # 直接用 AD URL 调用
    python anp_cli.py call "https://xxx/ad.json" some_method '{"key":"value"}'
    
    # 添加新 Agent
    python anp_cli.py add myagent "https://example.com/ad.json"
""")

async def main():
    if len(sys.argv) < 2:
        show_help()
        return
    
    cmd = sys.argv[1]
    
    if cmd in ["help", "-h", "--help"]:
        show_help()
    
    elif cmd == "connect":
        if len(sys.argv) < 3:
            print("用法: python anp_cli.py connect <ad_url>")
            return
        await connect(sys.argv[2])
    
    elif cmd == "call":
        if len(sys.argv) < 5:
            print("用法: python anp_cli.py call <id|ad_url> <method> '<params_json>'")
            return
        target = sys.argv[2]
        method = sys.argv[3]
        params = json.loads(sys.argv[4])
        await call_method(target, method, params)
    
    elif cmd == "add":
        if len(sys.argv) < 4:
            print("用法: python anp_cli.py add <id> <ad_url>")
            return
        await add_agent(sys.argv[2], sys.argv[3])
    
    elif cmd == "list":
        list_agents()
    
    elif cmd == "remove":
        if len(sys.argv) < 3:
            print("用法: python anp_cli.py remove <id>")
            return
        agent_id = sys.argv[2]
        agents_data = load_agents()
        agents_data["agents"] = [a for a in agents_data.get("agents", []) if a.get("id") != agent_id]
        save_agents(agents_data)
        print(f"已移除: {agent_id}")
    
    else:
        print(f"未知命令: {cmd}")
        show_help()

if __name__ == "__main__":
    asyncio.run(main())
