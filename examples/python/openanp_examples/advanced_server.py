#!/usr/bin/env python3
"""OpenANP 完整服务端示例。

展示所有高级功能：
1. @interface 的两种模式（content / link）
2. Context 注入和 Session 管理
3. 静态 Information（URL / Content 模式）
4. 动态 @information 装饰器
5. 构造函数依赖注入

Context 核心概念：
===================
Context 是 OpenANP 的核心特性之一，通过参数注入自动提供给方法。

【重要】ctx.did - 请求者身份识别
    - ctx.did 包含请求者的 DID（去中心化身份标识符）
    - 通过 DID 可以唯一识别是哪个 Agent 在调用你的服务
    - 这对于：用户追踪、权限控制、个性化服务 等场景至关重要
    - 示例：did:wba:example.com:user:alice

【重要】ctx.session - 自定义会话存储
    - Session 基于 DID 自动隔离，不同用户的数据互不影响
    - 可以存储任意自定义字段：ctx.session.set("key", value)
    - 读取字段：ctx.session.get("key", default_value)
    - 适用于：购物车、用户偏好、临时状态 等场景

运行命令：
    uvicorn examples.python.openanp_examples.advanced_server:app --port 8000

生成的端点：
    GET  /shop/ad.json                      - Agent Description
    GET  /shop/interface.json               - OpenRPC 接口文档（content 模式方法）
    GET  /shop/interface/checkout.json      - Checkout 方法的独立接口文档（link 模式）
    GET  /shop/products/featured.json       - 精选商品（动态 Information）
    POST /shop/rpc                          - JSON-RPC 端点
"""

from fastapi import FastAPI

from anp.openanp import (
    AgentConfig,
    Context,
    Information,
    anp_agent,
    information,
    interface,
)


@anp_agent(
    AgentConfig(
        name="Online Shop",
        did="did:wba:example.com:shop",
        prefix="/shop",
        description="功能完整的在线商店代理",
        tags=["shopping", "e-commerce"],
    )
)
class ShopAgent:
    """在线商店代理 - 展示 OpenANP 所有高级功能。"""

    # =========================================================================
    # 静态 Information 定义
    # =========================================================================
    informations = [
        # URL 模式：外部链接
        Information(
            type="ImageObject",
            description="商店 Logo",
            url="https://cdn.example.com/logo.png",
        ),
        # Content 模式：内嵌内容
        Information(
            type="Organization",
            description="联系方式",
            mode="content",
            content={
                "name": "Example Shop",
                "phone": "+86-10-12345678",
                "email": "contact@example.com",
            },
        ),
    ]

    def __init__(self, discount_rate: float = 0.1):
        """初始化商店代理。

        Args:
            discount_rate: 默认折扣率
        """
        self.discount_rate = discount_rate
        self._products = {
            "P001": {"name": "笔记本电脑", "price": 5999, "stock": 10},
            "P002": {"name": "无线鼠标", "price": 99, "stock": 50},
            "P003": {"name": "机械键盘", "price": 399, "stock": 30},
        }

    # =========================================================================
    # Content 模式接口（嵌入 interface.json）
    # =========================================================================

    @interface
    async def list_products(self) -> dict:
        """列出所有商品。

        Returns:
            商品列表
        """
        return {"products": list(self._products.values())}

    @interface
    async def get_product(self, product_id: str) -> dict:
        """获取商品详情。

        Args:
            product_id: 商品 ID

        Returns:
            商品详情
        """
        product = self._products.get(product_id)
        if not product:
            return {"error": "商品不存在"}
        return {"product": product}

    # =========================================================================
    # Context 注入演示
    # =========================================================================
    #
    # 【核心概念】Context 通过参数名 `ctx: Context` 自动注入
    #
    # ctx.did - 请求者的 DID 身份标识（非常重要！）
    #   - 通过 ctx.did 可以知道"是谁在调用我"
    #   - 用于：身份识别、权限控制、个性化服务、审计日志
    #   - 示例值：did:wba:example.com:user:alice
    #
    # ctx.session - 基于 DID 隔离的会话存储
    #   - 不同 DID 的用户数据自动隔离
    #   - 可存储任意自定义字段（购物车、偏好设置等）
    #   - get(key, default) / set(key, value) / clear()
    #
    # =========================================================================

    @interface
    async def add_to_cart(
        self, product_id: str, quantity: int, ctx: Context
    ) -> dict:
        """添加商品到购物车。

        演示：
        - ctx.did 获取请求者身份
        - ctx.session 存储自定义字段 "cart"

        Args:
            product_id: 商品 ID
            quantity: 数量
            ctx: 上下文（自动注入，无需客户端传递）

        Returns:
            购物车状态
        """
        # =====================================================================
        # 【重要】ctx.did - 识别请求者身份
        # =====================================================================
        # ctx.did 告诉我们"是谁在调用这个接口"
        # 这对于多用户系统至关重要：
        # - 不同用户的购物车需要隔离
        # - 可以基于 DID 做权限控制
        # - 可以记录用户行为日志
        caller_did = ctx.did
        print(f"[add_to_cart] 请求者 DID: {caller_did}")

        # =====================================================================
        # 【重要】ctx.session - 自定义会话字段
        # =====================================================================
        # Session 基于 DID 自动隔离，不同用户的数据互不影响
        # 可以存储任意自定义字段：cart、preferences、history 等

        # 读取自定义字段 "cart"，首次访问返回默认值 {}
        cart: dict = ctx.session.get("cart", {})

        # 更新购物车
        if product_id in cart:
            cart[product_id] += quantity
        else:
            cart[product_id] = quantity

        # 保存自定义字段 "cart" 到 Session
        ctx.session.set("cart", cart)

        # 也可以存储其他自定义字段
        ctx.session.set("last_action", "add_to_cart")
        ctx.session.set("last_product", product_id)

        return {
            "cart": cart,
            "caller_did": caller_did,  # 返回调用者 DID，客户端可以确认身份
            "message": f"已添加 {quantity} 件商品",
        }

    @interface
    async def get_cart(self, ctx: Context) -> dict:
        """获取当前购物车。

        演示：ctx.session 读取多个自定义字段

        Args:
            ctx: 上下文（自动注入）

        Returns:
            购物车内容和总价
        """
        # 读取自定义字段
        cart: dict = ctx.session.get("cart", {})
        last_action = ctx.session.get("last_action", None)

        total = 0
        items = []

        for product_id, quantity in cart.items():
            product = self._products.get(product_id)
            if product:
                subtotal = product["price"] * quantity
                total += subtotal
                items.append({
                    "product_id": product_id,
                    "name": product["name"],
                    "quantity": quantity,
                    "subtotal": subtotal,
                })

        # 应用折扣
        discount = total * self.discount_rate
        final_total = total - discount

        return {
            "items": items,
            "subtotal": total,
            "discount": discount,
            "discount_rate": self.discount_rate,
            "total": final_total,
            "caller_did": ctx.did,  # 请求者身份
            "last_action": last_action,  # 自定义字段示例
        }

    # =========================================================================
    # Link 模式接口（独立 interface 文件）
    # =========================================================================

    @interface(mode="link")
    async def checkout(self, address: str, ctx: Context) -> dict:
        """结算购物车。

        此方法使用 link 模式，会生成独立的 interface 文件。

        演示：
        - 使用 ctx.did 生成用户专属订单号
        - 使用 ctx.session.set() 清空购物车

        Args:
            address: 收货地址
            ctx: 上下文（自动注入）

        Returns:
            订单确认
        """
        cart: dict = ctx.session.get("cart", {})
        if not cart:
            return {"error": "购物车为空"}

        # 【重要】使用 ctx.did 生成用户专属订单号
        # 同一用户的订单号有规律，便于追踪
        order_id = f"ORD-{hash(ctx.did) % 100000:05d}"

        # 清空购物车（自定义字段可以随时覆盖）
        ctx.session.set("cart", {})

        # 记录订单历史（演示存储复杂数据结构）
        order_history: list = ctx.session.get("order_history", [])
        order_history.append({
            "order_id": order_id,
            "address": address,
        })
        ctx.session.set("order_history", order_history)

        return {
            "order_id": order_id,
            "address": address,
            "status": "confirmed",
            "caller_did": ctx.did,  # 订单归属者
            "total_orders": len(order_history),  # 该用户历史订单数
        }

    # =========================================================================
    # 动态 Information
    # =========================================================================

    @information(
        type="Product",
        description="今日精选商品",
        path="/products/featured.json",
    )
    def get_featured_products(self) -> dict:
        """获取精选商品（URL 模式，独立端点）。

        Returns:
            精选商品列表
        """
        return {
            "featured": [
                self._products["P001"],
                self._products["P003"],
            ],
            "updated_at": "2024-01-15",
        }

    @information(
        type="Offer",
        description="限时优惠",
        mode="content",
    )
    def get_special_offers(self) -> dict:
        """获取特别优惠（Content 模式，嵌入 ad.json）。

        Returns:
            优惠信息列表
        """
        return {
            "offers": [
                {"name": "新年特惠", "discount": "20%", "expires": "2024-02-01"},
                {"name": "满减活动", "condition": "满 500 减 50"},
            ]
        }


def create_app() -> FastAPI:
    """创建 FastAPI 应用。

    Returns:
        配置好的 FastAPI 应用实例
    """
    app = FastAPI(
        title="Online Shop Agent",
        description="OpenANP 完整服务端示例",
    )

    # 使用构造函数注入自定义配置
    agent = ShopAgent(discount_rate=0.15)  # 15% 折扣
    app.include_router(agent.router())

    return app


app = create_app()


if __name__ == "__main__":
    import uvicorn

    print("启动完整 ANP Server...")
    print("  Agent Description:    http://localhost:8000/shop/ad.json")
    print("  OpenRPC 文档:         http://localhost:8000/shop/interface.json")
    print("  Checkout 接口:        http://localhost:8000/shop/interface/checkout.json")
    print("  精选商品:             http://localhost:8000/shop/products/featured.json")
    print("  JSON-RPC 端点:        http://localhost:8000/shop/rpc")
    uvicorn.run(app, host="0.0.0.0", port=8000)
