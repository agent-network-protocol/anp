/**
 * @program: anp4java
 * @description: 在线商店 Agent - 对齐 Python advanced_server.py
 *               演示 Context 注入、Session 管理、购物车等高级功能
 * @author: Ruitao.Zhai
 * @date: 2025-01-29
 */
package com.agentconnect.example.springboot;

import com.agentconnect.server.Context;
import com.agentconnect.server.annotation.AnpAgent;
import com.agentconnect.server.annotation.Interface;
import com.agentconnect.server.annotation.Information;
import org.springframework.stereotype.Component;

import java.util.*;

@Component
@AnpAgent(
    name = "Online Shop",
    description = "A full-featured online shop agent with cart and checkout",
    did = "did:wba:example.com:shop",
    prefix = "/shop"
)
public class ShopAgent {
    
    private final double discountRate;
    private final Map<String, Map<String, Object>> products;
    
    public ShopAgent() {
        this.discountRate = 0.15;
        this.products = new LinkedHashMap<>();
        products.put("P001", createProduct("P001", "Laptop", 999.0, 10));
        products.put("P002", createProduct("P002", "Wireless Mouse", 29.0, 50));
        products.put("P003", createProduct("P003", "Mechanical Keyboard", 89.0, 30));
    }
    
    @Interface(
        name = "list_products",
        description = "List all available products"
    )
    public Map<String, Object> listProducts(Map<String, Object> params, Context ctx) {
        return Map.of(
            "products", new ArrayList<>(products.values()),
            "count", products.size()
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
    
    @Interface(
        name = "add_to_cart",
        description = "Add product to shopping cart"
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
        
        Map<String, Integer> cart = ctx.getSession().get("cart", new HashMap<String, Integer>());
        
        cart.put(productId, cart.getOrDefault(productId, 0) + quantity);
        ctx.getSession().set("cart", cart);
        ctx.getSession().set("last_action", "add_to_cart");
        ctx.getSession().set("last_product", productId);
        
        return Map.of(
            "cart", cart,
            "caller_did", ctx.getCallerDid() != null ? ctx.getCallerDid() : "anonymous",
            "message", "Added " + quantity + " item(s)"
        );
    }
    
    @Interface(
        name = "get_cart",
        description = "Get current shopping cart with total price"
    )
    @SuppressWarnings("unchecked")
    public Map<String, Object> getCart(Map<String, Object> params, Context ctx) {
        Map<String, Integer> cart = ctx.getSession().get("cart", new HashMap<String, Integer>());
        String lastAction = ctx.getSession().get("last_action");
        
        List<Map<String, Object>> items = new ArrayList<>();
        double total = 0;
        
        for (Map.Entry<String, Integer> entry : cart.entrySet()) {
            String productId = entry.getKey();
            int quantity = entry.getValue();
            Map<String, Object> product = products.get(productId);
            
            if (product != null) {
                double price = (Double) product.get("price");
                double subtotal = price * quantity;
                total += subtotal;
                
                items.add(Map.of(
                    "product_id", productId,
                    "name", product.get("name"),
                    "quantity", quantity,
                    "subtotal", subtotal
                ));
            }
        }
        
        double discount = total * discountRate;
        double finalTotal = total - discount;
        
        return Map.of(
            "items", items,
            "subtotal", total,
            "discount", discount,
            "discount_rate", discountRate,
            "total", finalTotal,
            "caller_did", ctx.getCallerDid() != null ? ctx.getCallerDid() : "anonymous",
            "last_action", lastAction != null ? lastAction : "none"
        );
    }
    
    @Interface(
        name = "checkout",
        description = "Checkout the shopping cart"
    )
    @SuppressWarnings("unchecked")
    public Map<String, Object> checkout(Map<String, Object> params, Context ctx) {
        String address = (String) params.get("address");
        if (address == null || address.isEmpty()) {
            return Map.of("error", "address is required");
        }
        
        Map<String, Integer> cart = ctx.getSession().get("cart", new HashMap<String, Integer>());
        
        if (cart.isEmpty()) {
            return Map.of("error", "Cart is empty");
        }
        
        String callerDid = ctx.getCallerDid() != null ? ctx.getCallerDid() : "anonymous";
        String orderId = "ORD-" + String.format("%05d", Math.abs(callerDid.hashCode()) % 100000);
        
        ctx.getSession().set("cart", new HashMap<String, Integer>());
        
        List<Map<String, Object>> orderHistory = ctx.getSession().get("order_history", new ArrayList<Map<String, Object>>());
        orderHistory.add(Map.of("order_id", orderId, "address", address));
        ctx.getSession().set("order_history", orderHistory);
        
        return Map.of(
            "order_id", orderId,
            "address", address,
            "status", "confirmed",
            "caller_did", callerDid,
            "total_orders", orderHistory.size()
        );
    }
    
    @Interface(
        name = "get_featured_products",
        description = "Get today's featured products"
    )
    public Map<String, Object> getFeaturedProducts(Map<String, Object> params, Context ctx) {
        List<Map<String, Object>> featured = Arrays.asList(
            products.get("P001"),
            products.get("P003")
        );
        
        return Map.of(
            "featured", featured,
            "updated_at", "2024-01-15"
        );
    }
    
    private static Map<String, Object> createProduct(String id, String name, double price, int stock) {
        Map<String, Object> product = new LinkedHashMap<>();
        product.put("id", id);
        product.put("name", name);
        product.put("price", price);
        product.put("stock", stock);
        return product;
    }
}
