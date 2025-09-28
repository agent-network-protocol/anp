#!/usr/bin/env python3
"""
ANPCrawler简单示例 - AMAP服务

这是一个简化的示例，展示如何快速使用ANPCrawler获取和调用AMAP服务。
"""

import asyncio
import json
import sys
from pathlib import Path

# 添加项目路径
project_root = Path(__file__).parent.parent.parent.parent
sys.path.insert(0, str(project_root))

from agent_connect.anp_crawler.anp_crawler import ANPCrawler


async def simple_amap_example():
    """简单的AMAP服务示例"""

    # 1. 初始化爬虫
    crawler = ANPCrawler(
        did_document_path=str(project_root / "docs" / "did_public" / "public-did-doc.json"),
        private_key_path=str(project_root / "docs" / "did_public" / "public-private-key.pem")
    )

    # 2. 目标URL
    url = "https://agent-connect.ai/agents/travel/mcp/agents/amap/ad.json"

    print("步骤1: 获取AMAP代理描述文档")
    print("-" * 40)

    # 3. 获取代理描述
    content_json, interfaces_list = await crawler.fetch_text(url)

    # 4. 打印ad.json内容
    print("代理描述文档内容:")
    try:
        parsed_content = json.loads(content_json["content"])
        print(json.dumps(parsed_content, indent=2, ensure_ascii=False))
    except:
        print(content_json["content"])

    print(f"\n步骤2: 发现的接口数量: {len(interfaces_list)}")
    print("-" * 40)

    # 5. 显示可用的工具
    tools = crawler.list_available_tools()
    print(f"可用工具: {tools}")

    # 6. 如果有工具可用，尝试调用
    if tools:
        tool_name = tools[0]
        print(f"\n步骤3: 尝试调用工具 '{tool_name}'")
        print("-" * 40)

        # 示例参数 (需要根据实际接口调整)
        test_arguments = {
            "query": "天安门广场"
        }

        try:
            result = await crawler.execute_tool_call(tool_name, test_arguments)
            print("调用结果:")
            print(json.dumps(result, indent=2, ensure_ascii=False))
        except Exception as e:
            print(f"调用失败: {e}")

    print("\n会话信息:")
    print(f"- 访问的URL: {crawler.get_visited_urls()}")
    print(f"- 缓存条目数: {crawler.get_cache_size()}")


if __name__ == "__main__":
    asyncio.run(simple_amap_example())