#!/usr/bin/env python3
"""OpenANP 完整客户端示例。

展示所有客户端功能：
1. 代理发现和方法列表
2. 动态属性调用 vs 显式调用
3. OpenAI Tools 格式导出（LLM 集成）
4. Session 会话管理演示
5. 错误处理

前提条件：
    先启动 advanced_server.py：
    uvicorn examples.python.openanp_examples.advanced_server:app --port 8000

运行命令：
    uv run python examples/python/openanp_examples/advanced_client.py
"""

import asyncio
import json
from pathlib import Path

from anp.authentication import DIDWbaAuthHeader
from anp.openanp import RemoteAgent


# DID 文档和私钥路径
PROJECT_ROOT = Path(__file__).parent.parent.parent.parent
DID_DOC = PROJECT_ROOT / "docs/did_public/public-did-doc.json"
PRIVATE_KEY = PROJECT_ROOT / "docs/did_public/public-private-key.pem"


def print_section(title: str) -> None:
    """打印分隔线。

    Args:
        title: 章节标题
    """
    print(f"\n{'=' * 60}")
    print(f" {title}")
    print("=" * 60)


async def main() -> None:
    """完整客户端演示。"""
    # =========================================================================
    # 1. 初始化认证
    # =========================================================================
    print_section("1. 初始化认证")
    auth = DIDWbaAuthHeader(
        did_document_path=str(DID_DOC),
        private_key_path=str(PRIVATE_KEY),
    )
    print("✓ 认证已创建")

    # =========================================================================
    # 2. 发现代理
    # =========================================================================
    print_section("2. 发现代理")
    try:
        agent = await RemoteAgent.discover(
            "http://localhost:8000/shop/ad.json",
            auth,
        )
    except Exception as e:
        print(f"✗ 连接失败: {e}")
        print("\n请先启动服务端:")
        print("  uvicorn examples.python.openanp_examples.advanced_server:app --port 8000")
        return

    print(f"名称: {agent.name}")
    print(f"描述: {agent.description}")
    print(f"URL:  {agent.url}")

    # =========================================================================
    # 3. 查看可用方法
    # =========================================================================
    print_section("3. 可用方法")
    for i, method in enumerate(agent.methods, 1):
        print(f"\n  [{i}] {method.name}")
        print(f"      描述: {method.description}")
        if method.params:
            params = [p.get("name", "?") for p in method.params]
            print(f"      参数: {', '.join(params)}")

    # =========================================================================
    # 4. OpenAI Tools 格式（LLM 集成）
    # =========================================================================
    print_section("4. OpenAI Tools 格式")
    tools = agent.tools
    print(f"共 {len(tools)} 个工具可用于 LLM")
    if tools:
        print("\n示例（第一个工具）:")
        tool_str = json.dumps(tools[0], indent=2, ensure_ascii=False)
        # 截断过长的输出
        if len(tool_str) > 500:
            tool_str = tool_str[:500] + "..."
        print(tool_str)

    # =========================================================================
    # 5. 调用方法 - 动态属性
    # =========================================================================
    print_section("5. 调用方法 - 动态属性")

    # 列出商品
    result = await agent.list_products()
    print("商品列表:")
    for p in result.get("products", []):
        print(f"  - {p['name']}: ¥{p['price']}")

    # 获取单个商品
    result = await agent.get_product(product_id="P001")
    print(f"\n商品详情: {result}")

    # =========================================================================
    # 6. 调用方法 - 显式调用
    # =========================================================================
    print_section("6. 调用方法 - 显式调用")

    result = await agent.call("get_product", product_id="P002")
    print(f"使用 call() 获取商品: {result}")

    # =========================================================================
    # 7. Session 会话演示 - Context 核心功能
    # =========================================================================
    print_section("7. Session 会话演示")

    # 添加商品到购物车
    print("添加商品到购物车...")
    result1 = await agent.add_to_cart(product_id="P001", quantity=2)
    result2 = await agent.add_to_cart(product_id="P002", quantity=3)

    # 【重要】服务端通过 ctx.did 识别了我们的身份
    print(f"\n服务端识别的调用者 DID: {result2.get('caller_did')}")

    # 查看购物车
    cart = await agent.get_cart()
    print("\n购物车内容:")
    for item in cart.get("items", []):
        print(f"  - {item['name']} x{item['quantity']} = ¥{item['subtotal']}")
    print(f"\n小计: ¥{cart.get('subtotal', 0)}")
    print(f"折扣: -¥{cart.get('discount', 0):.2f} ({cart.get('discount_rate', 0)*100:.0f}%)")
    print(f"总计: ¥{cart.get('total', 0):.2f}")

    # 服务端存储的自定义字段
    print(f"\n服务端自定义字段 last_action: {cart.get('last_action')}")

    # 结算
    print("\n结算订单...")
    order = await agent.checkout(address="北京市朝阳区xxx街道")
    print(f"订单号: {order.get('order_id')}")
    print(f"状态: {order.get('status')}")
    print(f"该用户历史订单数: {order.get('total_orders')}")

    # =========================================================================
    # 8. 错误处理
    # =========================================================================
    print_section("8. 错误处理")

    # 调用不存在的方法
    try:
        await agent.non_existent_method()
    except AttributeError as e:
        print(f"✓ 捕获 AttributeError: {e}")

    print_section("演示完成")


if __name__ == "__main__":
    asyncio.run(main())
