#!/usr/bin/env python3
"""
ANPCrawler示例代码 - AMAP服务

此示例展示如何使用ANPCrawler访问AMAP代理服务并调用其JSON-RPC接口。
"""

import asyncio
import json
import logging
import os
import sys
from pathlib import Path

# 添加项目根目录到路径，以便导入agent_connect模块
project_root = Path(__file__).parent.parent.parent.parent
sys.path.insert(0, str(project_root))

from agent_connect.anp_crawler.anp_crawler import ANPCrawler

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class AmapCrawlerExample:
    """AMAP服务爬虫示例类"""

    def __init__(self):
        # 使用公共DID文档和私钥文件路径
        self.did_document_path = str(project_root / "docs" / "did_public" / "public-did-doc.json")
        self.private_key_path = str(project_root / "docs" / "did_public" / "public-private-key.pem")

        # AMAP代理描述URL
        self.agent_description_url = "https://agent-connect.ai/agents/travel/mcp/agents/amap/ad.json"

        # 检查必需的文件是否存在
        self._check_required_files()

        # 初始化爬虫
        self.crawler = ANPCrawler(
            did_document_path=self.did_document_path,
            private_key_path=self.private_key_path,
            cache_enabled=True
        )

    def _check_required_files(self):
        """检查必需的DID文档和私钥文件是否存在"""
        if not os.path.exists(self.did_document_path):
            raise FileNotFoundError(f"DID文档文件不存在: {self.did_document_path}")
        if not os.path.exists(self.private_key_path):
            raise FileNotFoundError(f"私钥文件不存在: {self.private_key_path}")

    async def fetch_agent_description(self):
        """获取并打印代理描述文档"""
        logger.info("正在获取AMAP代理描述文档...")

        try:
            # 使用fetch_text方法获取代理描述
            content_json, interfaces_list = await self.crawler.fetch_text(self.agent_description_url)

            # 打印原始内容
            print("\n" + "="*60)
            print("AMAP代理描述文档内容:")
            print("="*60)

            # 解析并美化打印JSON内容
            try:
                parsed_content = json.loads(content_json["content"])
                print(json.dumps(parsed_content, indent=2, ensure_ascii=False))
            except json.JSONDecodeError:
                # 如果不是JSON格式，直接打印原始内容
                print(content_json["content"])

            print("\n" + "="*60)
            print(f"发现的接口数量: {len(interfaces_list)}")
            print("="*60)

            # 打印发现的接口
            for i, interface in enumerate(interfaces_list, 1):
                print(f"\n接口 {i}:")
                print(f"  函数名: {interface.get('function', {}).get('name', 'N/A')}")
                print(f"  描述: {interface.get('function', {}).get('description', 'N/A')}")

                parameters = interface.get('function', {}).get('parameters', {})
                if parameters.get('properties'):
                    print("  参数:")
                    for param_name, param_info in parameters['properties'].items():
                        param_type = param_info.get('type', 'unknown')
                        param_desc = param_info.get('description', '无描述')
                        print(f"    - {param_name} ({param_type}): {param_desc}")

            return content_json, interfaces_list

        except Exception as e:
            logger.error(f"获取代理描述失败: {str(e)}")
            raise

    async def fetch_interface_specifications(self):
        """获取接口规格文档"""
        # 从代理描述中提取接口URL
        content_json, _ = await self.crawler.fetch_text(self.agent_description_url)

        try:
            agent_desc = json.loads(content_json["content"])

            # 遍历interfaces数组
            for interface_info in agent_desc.get("interfaces", []):
                if interface_info.get("type") == "structuredInterface":
                    interface_url = interface_info.get("url")
                    if interface_url:
                        logger.info(f"正在获取接口规格: {interface_url}")

                        # 获取接口规格文档
                        spec_content, spec_interfaces = await self.crawler.fetch_text(interface_url)

                        print("\n" + "="*60)
                        print(f"接口规格文档: {interface_url}")
                        print("="*60)

                        # 解析并打印接口规格
                        try:
                            spec_json = json.loads(spec_content["content"])
                            print(json.dumps(spec_json, indent=2, ensure_ascii=False))
                        except json.JSONDecodeError:
                            print(spec_content["content"])

                        return spec_content, spec_interfaces

        except Exception as e:
            logger.error(f"获取接口规格失败: {str(e)}")
            raise

    async def list_available_tools(self):
        """列出所有可用的工具"""
        tools = self.crawler.list_available_tools()

        print("\n" + "="*60)
        print("可用的工具列表:")
        print("="*60)

        if not tools:
            print("未发现任何可用工具")
            return []

        for i, tool_name in enumerate(tools, 1):
            print(f"{i}. {tool_name}")

            # 获取工具的详细信息
            tool_info = self.crawler.get_tool_interface_info(tool_name)
            if tool_info:
                print(f"   方法名: {tool_info.get('method_name', 'N/A')}")
                print(f"   服务器: {tool_info.get('servers', 'N/A')}")

        return tools

    async def demonstrate_tool_call(self, tool_name: str, arguments: dict):
        """演示工具调用"""
        print("\n" + "="*60)
        print(f"正在调用工具: {tool_name}")
        print(f"参数: {json.dumps(arguments, indent=2, ensure_ascii=False)}")
        print("="*60)

        try:
            result = await self.crawler.execute_tool_call(tool_name, arguments)

            print("调用结果:")
            print(json.dumps(result, indent=2, ensure_ascii=False))

            return result

        except Exception as e:
            logger.error(f"工具调用失败: {str(e)}")
            print(f"错误: {str(e)}")
            return None

    async def run_example(self):
        """运行完整示例"""
        try:
            print("ANPCrawler AMAP服务示例")
            print("="*60)

            # 1. 获取并打印代理描述
            await self.fetch_agent_description()

            # 2. 获取接口规格
            await self.fetch_interface_specifications()

            # 3. 列出可用工具
            tools = await self.list_available_tools()

            # 4. 如果有可用工具，演示调用
            if tools:
                # 尝试调用第一个工具（如果存在）
                first_tool = tools[0]

                # 示例参数 - 这里需要根据实际接口调整
                sample_arguments = {
                    "query": "北京天安门",
                    "city": "北京"
                }

                print(f"\n尝试调用工具: {first_tool}")
                print("注意: 这是一个示例调用，实际参数需要根据接口规格调整")

                await self.demonstrate_tool_call(first_tool, sample_arguments)

            # 5. 显示会话统计
            print("\n" + "="*60)
            print("会话统计:")
            print("="*60)
            print(f"访问的URL数量: {len(self.crawler.get_visited_urls())}")
            print(f"缓存条目数量: {self.crawler.get_cache_size()}")
            print("访问的URL列表:")
            for url in self.crawler.get_visited_urls():
                print(f"  - {url}")

        except Exception as e:
            logger.error(f"示例运行失败: {str(e)}")
            raise


async def main():
    """主函数"""
    try:
        example = AmapCrawlerExample()
        await example.run_example()

    except FileNotFoundError as e:
        print(f"文件错误: {e}")
        print("\n请确保以下文件存在:")
        print("- docs/did_public/public-did-doc.json")
        print("- docs/did_public/public-private-key.pem")

    except Exception as e:
        logger.error(f"示例执行失败: {str(e)}")
        print(f"\n错误: {str(e)}")


if __name__ == "__main__":
    asyncio.run(main())