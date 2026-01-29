/**
 * @program: anp4java
 * @description: AP2 支付协议概念示例
 * @author: Ruitao.Zhai
 * @date: 2025-01-29
 **/
package com.agentconnect.example.advanced;

import com.agentconnect.server.Context;
import com.agentconnect.server.annotation.AnpAgent;
import com.agentconnect.server.annotation.Information;
import com.agentconnect.server.annotation.Interface;
import com.agentconnect.protocol.RPCMethodInfo;
import org.springframework.stereotype.Component;

import java.util.*;


@Component
@AnpAgent(
    name = "Advanced Shop",
    description = "Full-featured online shop agent demonstrating all ANP features",
    did = "did:wba:example.com:advanced-shop",
    prefix = "/advanced-shop",
    tags = {"shopping", "e-commerce", "demo"}
)
public class AdvancedShopAgent {
    /**
     * 高级商店 Agent 演示OpenANP 功能。
     *
     * 演示的功能：
     * - 内容模式接口（嵌入在 interface.json 中）
     * - 链接模式接口（单独的接口文件）
     * - URL 模式信息（外部/托管 URL）
     * - 内容模式信息（嵌入在 ad.json 中）
     * - 上下文和会话注入
     * - 基于 DID 隔离的购物车
     */
    private final double discountRate;
    private final Map<String, Map<String, Object>> products;
    
    /**
     * 带有依赖注入的构造函数。
     * 在 Spring 中，您可以注入服务、存储库等。
     */
    public AdvancedShopAgent() {
        this.discountRate = 0.15; // 15% discount
        this.products = new LinkedHashMap<>();
        products.put("P001", createProduct("P001", "Laptop", 999.0, 10));
        products.put("P002", createProduct("P002", "Wireless Mouse", 29.0, 50));
        products.put("P003", createProduct("P003", "Mechanical Keyboard", 89.0, 30));
        products.put("P004", createProduct("P004", "4K Monitor", 399.0, 15));
        products.put("P005", createProduct("P005", "USB-C Hub", 49.0, 100));
    }
    
    // =========================================================================
    // 内容模式接口（嵌入在 interface.json 中）
    // =========================================================================
    
    @Interface(
        name = "list_products",
        description = "List all available products"
    )
    public Map<String, Object> listProducts(Map<String, Object> params, Context ctx) {
        return Map.of(
            "products", new ArrayList<>(products.values()),
            "count", products.size(),
            "discount_rate", discountRate
        );
    }
    
    @Interface(
        name = "get_product",
        description = "Get product details by ID"
    )
    public Map<String, Object> getProduct(Map<String, Object> params, Context ctx) {
        String productId = (String) params.get("product_id");
        if (productId == null) {
            return Map.of("error", "product_id is required");
        }
        
        Map<String, Object> product = products.get(productId);
        if (product == null) {
            return Map.of("error", "Product not found: " + productId);
        }
        
        return Map.of("product", product);
    }
    
    // =========================================================================
    // 上下文注入演示 - 购物车
    // =========================================================================
    
    /**
     * 将产品添加到购物车。
     * 
     * 演示：
     * - ctx.getDid() 获取调用者身份
     * - ctx.getSession() 存储自定义数据（购物车）
     * - 会话按 DID 自动隔离
     */
    @Interface(
        name = "add_to_cart",
        description = "Add product to shopping cart (session-based)"
    )
    @SuppressWarnings("unchecked")
    public Map<String, Object> addToCart(Map<String, Object> params, Context ctx) {
        String productId = (String) params.get("product_id");
        int quantity = params.get("quantity") != null 
            ? ((Number) params.get("quantity")).intValue() 
            : 1;
        
        if (productId == null) {
            return Map.of("error", "product_id is required");
        }
        
        if (!products.containsKey(productId)) {
            return Map.of("error", "Product not found: " + productId);
        }
        
        // 从会话中获取或创建购物车（按 DID 隔离）
        Map<String, Integer> cart = ctx.getSession().get("cart", new HashMap<>());
        
        // 更新购物车
        cart.put(productId, cart.getOrDefault(productId, 0) + quantity);
        
        // 保存回会话
        ctx.getSession().set("cart", cart);
        ctx.getSession().set("last_action", "add_to_cart");
        ctx.getSession().set("last_product", productId);
        
        String callerDid = ctx.getDid() != null ? ctx.getDid() : "anonymous";
        
        return Map.of(
            "success", true,
            "cart", cart,
            "caller_did", callerDid,
            "message", "Added " + quantity + " x " + products.get(productId).get("name")
        );
    }
    
    @Interface(
        name = "get_cart",
        description = "Get current shopping cart with total price"
    )
    @SuppressWarnings("unchecked")
    public Map<String, Object> getCart(Map<String, Object> params, Context ctx) {
        Map<String, Integer> cart = ctx.getSession().get("cart", new HashMap<>());
        String lastAction = ctx.getSession().get("last_action");
        
        List<Map<String, Object>> items = new ArrayList<>();
        double subtotal = 0;
        
        for (Map.Entry<String, Integer> entry : cart.entrySet()) {
            String productId = entry.getKey();
            int quantity = entry.getValue();
            Map<String, Object> product = products.get(productId);
            
            if (product != null) {
                double price = (Double) product.get("price");
                double itemTotal = price * quantity;
                subtotal += itemTotal;
                
                items.add(Map.of(
                    "product_id", productId,
                    "name", product.get("name"),
                    "price", price,
                    "quantity", quantity,
                    "subtotal", itemTotal
                ));
            }
        }
        
        double discount = subtotal * discountRate;
        double total = subtotal - discount;
        
        String callerDid = ctx.getDid() != null ? ctx.getDid() : "anonymous";
        
        return Map.of(
            "items", items,
            "subtotal", subtotal,
            "discount", discount,
            "discount_rate", discountRate,
            "total", total,
            "caller_did", callerDid,
            "last_action", lastAction != null ? lastAction : "none"
        );
    }
    
    // =========================================================================
    // 链接模式接口（单独的接口文件）
    // =========================================================================
    
    /**
     * 结账购物车。
     * 
     * 使用链接模式 - 生成一个单独的接口文件位于：
     * /advanced-shop/interface/checkout.json
     */
    @Interface(
        name = "checkout",
        description = "Checkout the shopping cart and place order",
        mode = RPCMethodInfo.Mode.LINK
    )
    @SuppressWarnings("unchecked")
    public Map<String, Object> checkout(Map<String, Object> params, Context ctx) {
        String address = (String) params.get("address");
        if (address == null || address.isEmpty()) {
            return Map.of("error", "address is required");
        }
        
        Map<String, Integer> cart = ctx.getSession().get("cart", new HashMap<>());
        
        if (cart.isEmpty()) {
            return Map.of("error", "Cart is empty");
        }
        
        // 计算总价
        double total = 0;
        List<Map<String, Object>> orderItems = new ArrayList<>();
        
        for (Map.Entry<String, Integer> entry : cart.entrySet()) {
            String productId = entry.getKey();
            int quantity = entry.getValue();
            Map<String, Object> product = products.get(productId);
            
            if (product != null) {
                double price = (Double) product.get("price");
                double itemTotal = price * quantity;
                total += itemTotal;
                
                orderItems.add(Map.of(
                    "product_id", productId,
                    "name", product.get("name"),
                    "quantity", quantity,
                    "price", price
                ));
            }
        }
        
        // 应用折扣
        double discount = total * discountRate;
        double finalTotal = total - discount;
        
        // 基于 DID 生成订单 ID
        String callerDid = ctx.getDid() != null ? ctx.getDid() : "anonymous";
        String orderId = "ORD-" + String.format("%05d", Math.abs(callerDid.hashCode()) % 100000);
        
        // 清空购物车
        ctx.getSession().set("cart", new HashMap<String, Integer>());
        
        // 记录订单历史
        List<Map<String, Object>> orderHistory = ctx.getSession().get("order_history", new ArrayList<>());
        Map<String, Object> order = new LinkedHashMap<>();
        order.put("order_id", orderId);
        order.put("address", address);
        order.put("items", orderItems);
        order.put("total", finalTotal);
        order.put("timestamp", System.currentTimeMillis());
        orderHistory.add(order);
        ctx.getSession().set("order_history", orderHistory);
        
        return Map.of(
            "success", true,
            "order_id", orderId,
            "address", address,
            "items", orderItems,
            "subtotal", total,
            "discount", discount,
            "total", finalTotal,
            "status", "confirmed",
            "caller_did", callerDid,
            "total_orders", orderHistory.size()
        );
    }
    
    // =========================================================================
    // 信息端点（用于 ad.json）
    // =========================================================================
    
    /**
     * 获取特色产品。
     * URL 模式 - 在 /advanced-shop/products/featured.json 生成端点
     */
    @Information(
        type = "Product",
        description = "Today's featured products",
        mode = Information.Mode.URL,
        path = "/products/featured.json"
    )
    public Map<String, Object> getFeaturedProducts() {
        return Map.of(
            "featured", Arrays.asList(
                products.get("P001"),
                products.get("P004")
            ),
            "updated_at", "2024-01-15"
        );
    }
    
    /**
     * 获取特惠。
     * 内容模式 - 直接嵌入在 ad.json 中
     */
    @Information(
        type = "Offer",
        description = "Current special offers",
        mode = Information.Mode.CONTENT
    )
    public Map<String, Object> getSpecialOffers() {
        return Map.of(
            "offers", Arrays.asList(
                Map.of(
                    "name", "New Year Sale",
                    "discount", "20%",
                    "expires", "2025-02-01"
                ),
                Map.of(
                    "name", "Bundle Deal",
                    "condition", "Buy Laptop + Monitor, save $100"
                )
            )
        );
    }
    
    /**
     * 获取联系信息。
     * 内容模式 - 嵌入在 ad.json 中
     */
    @Information(
        type = "Organization",
        description = "Shop contact information",
        mode = Information.Mode.CONTENT
    )
    public Map<String, Object> getContactInfo() {
        return Map.of(
            "name", "Advanced Shop",
            "phone", "+1-800-SHOP",
            "email", "support@advanced-shop.example.com",
            "hours", "24/7"
        );
    }
    
    // =========================================================================
    // 辅助方法
    // =========================================================================
    
    private static Map<String, Object> createProduct(String id, String name, double price, int stock) {
        Map<String, Object> product = new LinkedHashMap<>();
        product.put("id", id);
        product.put("name", name);
        product.put("price", price);
        product.put("stock", stock);
        return product;
    }
}
