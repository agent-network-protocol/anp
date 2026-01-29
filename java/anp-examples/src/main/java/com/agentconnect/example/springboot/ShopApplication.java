/**
 * @program: anp4java
 * @description: 在线商店 Spring Boot 启动类 - 对齐 Python advanced_server.py
 * @author: Ruitao.Zhai
 * @date: 2025-01-29
 */
package com.agentconnect.example.springboot;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication(scanBasePackages = {
    "com.agentconnect.spring",
    "com.agentconnect.example.springboot"
})
public class ShopApplication {
    
    public static void main(String[] args) {
        SpringApplication.run(ShopApplication.class, args);
        printUsage();
    }
    
    private static void printUsage() {
        System.out.println();
        System.out.println("════════════════════════════════════════════════════════════");
        System.out.println("  🛒 Online Shop Agent 已启动");
        System.out.println("════════════════════════════════════════════════════════════");
        System.out.println();
        System.out.println("【端点】");
        System.out.println("  GET  http://localhost:8080/shop/ad.json");
        System.out.println("  GET  http://localhost:8080/shop/interface.json");
        System.out.println("  POST http://localhost:8080/shop/rpc");
        System.out.println();
        System.out.println("────────────────────────────────────────────────────────────");
        System.out.println("【测试流程】在另一个终端执行:");
        System.out.println("────────────────────────────────────────────────────────────");
        System.out.println();
        System.out.println("1. 查看商品列表:");
        System.out.println("   curl -X POST http://localhost:8080/shop/rpc \\");
        System.out.println("     -H \"Content-Type: application/json\" \\");
        System.out.println("     -d '{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"list_products\",\"params\":{}}'");
        System.out.println();
        System.out.println("2. 添加商品到购物车:");
        System.out.println("   curl -X POST http://localhost:8080/shop/rpc \\");
        System.out.println("     -H \"Content-Type: application/json\" \\");
        System.out.println("     -d '{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"add_to_cart\",\"params\":{\"product_id\":\"P001\",\"quantity\":2}}'");
        System.out.println();
        System.out.println("3. 查看购物车:");
        System.out.println("   curl -X POST http://localhost:8080/shop/rpc \\");
        System.out.println("     -H \"Content-Type: application/json\" \\");
        System.out.println("     -d '{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"get_cart\",\"params\":{}}'");
        System.out.println();
        System.out.println("4. 结算:");
        System.out.println("   curl -X POST http://localhost:8080/shop/rpc \\");
        System.out.println("     -H \"Content-Type: application/json\" \\");
        System.out.println("     -d '{\"jsonrpc\":\"2.0\",\"id\":4,\"method\":\"checkout\",\"params\":{\"address\":\"北京市朝阳区xxx\"}}'");
        System.out.println();
        System.out.println("────────────────────────────────────────────────────────────");
        System.out.println("【商品列表】");
        System.out.println("  P001 - Laptop         $999");
        System.out.println("  P002 - Wireless Mouse $29");
        System.out.println("  P003 - Mechanical KB  $89");
        System.out.println("────────────────────────────────────────────────────────────");
        System.out.println("按 Ctrl+C 停止服务");
        System.out.println("════════════════════════════════════════════════════════════");
    }
}
