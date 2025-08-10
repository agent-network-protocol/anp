#!/usr/bin/env python3
"""
ANP Crawler 嵌入式 OpenRPC 功能演示

此脚本演示如何使用 ANP Crawler 解析包含嵌入式 OpenRPC 内容的 Agent Description 文档。
"""

import json
import asyncio
import sys
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

# Add parent directory to path for imports
sys.path.append(str(Path(__file__).parent.parent.parent.parent))

from octopus.anp_sdk.anp_crawler.anp_crawler import ANPCrawler
from octopus.anp_sdk.anp_crawler.anp_parser import ANPDocumentParser
from octopus.anp_sdk.anp_crawler.anp_interface import ANPInterface


def print_separator(title: str):
    """Print a section separator."""
    print(f"\n{'='*60}")
    print(f"{title:^60}")
    print(f"{'='*60}")


def print_subsection(title: str):
    """Print a subsection header."""
    print(f"\n{'-'*40}")
    print(f"{title}")
    print(f"{'-'*40}")


async def demo_embedded_openrpc():
    """演示嵌入式 OpenRPC 功能."""
    
    print_separator("ANP Crawler 嵌入式 OpenRPC 功能演示")
    
    # Load test data
    test_data_dir = Path(__file__).parent
    with open(test_data_dir / "test_data_embedded_openrpc.json", "r") as f:
        embedded_openrpc_data = json.load(f)
    
    print_subsection("1. Agent Description 文档结构")
    print(f"Agent Name: {embedded_openrpc_data['name']}")
    print(f"Agent URL: {embedded_openrpc_data['url']}")
    print(f"Description: {embedded_openrpc_data['description']}")
    print(f"Total Interfaces: {len(embedded_openrpc_data['interfaces'])}")
    
    # Show interfaces structure
    for i, interface in enumerate(embedded_openrpc_data['interfaces']):
        print(f"\nInterface {i+1}:")
        print(f"  Type: {interface['type']}")
        print(f"  Protocol: {interface['protocol']}")
        print(f"  Has Content: {'content' in interface}")
        if 'content' in interface:
            content = interface['content']
            if 'methods' in content:
                print(f"  Embedded Methods: {len(content['methods'])}")
                for method in content['methods']:
                    print(f"    - {method['name']}: {method['summary']}")
    
    print_subsection("2. 使用 ANPDocumentParser 直接解析")
    
    # Test parser directly
    parser = ANPDocumentParser()
    content = json.dumps(embedded_openrpc_data)
    parsed_result = parser.parse_document(content, "application/json", "test_url")
    
    print(f"解析结果:")
    print(f"  提取的接口数量: {len(parsed_result['interfaces'])}")
    
    for interface in parsed_result['interfaces']:
        method_name = interface.get('method_name', interface.get('description', 'Unknown'))
        print(f"\n  接口: {method_name}")
        print(f"    类型: {interface['type']}")
        print(f"    协议: {interface['protocol']}")
        print(f"    来源: {interface['source']}")
        if 'params' in interface:
            print(f"    参数数量: {len(interface['params'])}")
        if 'components' in interface:
            print(f"    组件定义: {len(interface.get('components', {}).get('schemas', {}))}")
    
    print_subsection("3. 使用 ANPInterface 转换为 OpenAI Tools")
    
    # Test interface conversion
    converter = ANPInterface()
    converted_tools = []
    
    for interface in parsed_result['interfaces']:
        if interface['type'] == 'openrpc_method':
            tool = converter.convert_to_openai_tools(interface)
            if tool:
                converted_tools.append(tool)
                print(f"\n转换工具: {tool['function']['name']}")
                print(f"  描述: {tool['function']['description']}")
                params = tool['function']['parameters']
                print(f"  参数类型: {params['type']}")
                print(f"  属性数量: {len(params.get('properties', {}))}")
                print(f"  必需参数: {params.get('required', [])}")
                
                # Show $ref resolution example
                if tool['function']['name'] == 'createBooking':
                    booking_details = params['properties'].get('bookingDetails', {})
                    bd_props = booking_details.get('properties', {})
                    if 'guestInfo' in bd_props:
                        guest_info = bd_props['guestInfo']
                        if 'properties' in guest_info:
                            print(f"    ✅ $ref 解析成功: guestInfo 包含 {len(guest_info['properties'])} 个属性")
                            print(f"       属性: {list(guest_info['properties'].keys())}")
    
    print_subsection("4. 使用 ANPCrawler 完整流程演示")
    
    # Create mock crawler
    with patch('octopus.anp_sdk.anp_crawler.anp_client.DIDWbaAuthHeader') as mock_auth:
        mock_auth.return_value = MagicMock()
        
        crawler = ANPCrawler(
            did_document_path="test/did.json",
            private_key_path="test/private_key.json"
        )
        
        # Mock HTTP response
        mock_response = {
            "success": True,
            "text": json.dumps(embedded_openrpc_data),
            "content_type": "application/json",
            "status_code": 200,
            "url": "https://hotel-services.com/agents/booking-assistant"
        }
        
        crawler._client.fetch_url = AsyncMock(return_value=mock_response)
        
        # Execute fetch_text
        content_json, interfaces_list = await crawler.fetch_text(
            "https://hotel-services.com/agents/booking-assistant"
        )
        
        print(f"Crawler 结果:")
        print(f"  Agent Description URI: {content_json['agentDescriptionURI']}")
        print(f"  Content URI: {content_json['contentURI']}")
        print(f"  原始内容长度: {len(content_json['content'])} 字符")
        print(f"  提取的工具数量: {len(interfaces_list)}")
        
        print(f"\n提取的工具列表:")
        for i, tool in enumerate(interfaces_list):
            func = tool['function']
            print(f"  {i+1}. {func['name']}")
            print(f"     描述: {func['description']}")
            print(f"     参数数量: {len(func['parameters'].get('properties', {}))}")
    
    print_subsection("5. 功能特性总结")
    
    features = [
        "✅ 支持嵌入式 OpenRPC 内容解析",
        "✅ 自动识别 StructuredInterface + openrpc + content 模式",
        "✅ 完整的 $ref 引用解析（包括多层嵌套）",
        "✅ 统一的 OpenAI Tools 格式输出",
        "✅ 与传统 URL 引用接口的兼容性",
        "✅ 错误处理和内容验证",
        "✅ 会话管理和缓存支持"
    ]
    
    for feature in features:
        print(f"  {feature}")
    
    print_subsection("6. 使用场景")
    
    use_cases = [
        "🎯 自包含的 Agent Description 文档",
        "🎯 减少外部依赖的接口定义",
        "🎯 简化部署和分发的场景",
        "🎯 离线环境下的接口定义",
        "🎯 版本控制中的单文件管理",
        "🎯 快速原型开发和测试"
    ]
    
    for use_case in use_cases:
        print(f"  {use_case}")
    
    print(f"\n{'='*60}")
    print("演示完成! 🎉")
    print(f"{'='*60}")


if __name__ == "__main__":
    asyncio.run(demo_embedded_openrpc())