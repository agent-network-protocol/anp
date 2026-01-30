/**
 * @program: anp4java
 * @description: Hotel Booking Agent - Spring Boot Application
 * @author: Ruitao.Zhai
 * @date: 2025-01-20
 */
package com.agentconnect.example.springboot;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication(scanBasePackages = {
    "com.agentconnect.spring",
    "com.agentconnect.example.springboot"
})
public class HotelApplication {
    
    public static void main(String[] args) {
        SpringApplication.run(HotelApplication.class, args);
        printUsage();
    }
    
    private static void printUsage() {
        System.out.println();
        System.out.println("════════════════════════════════════════════════════════════");
        System.out.println("  🏨 Hotel Booking Agent 已启动");
        System.out.println("════════════════════════════════════════════════════════════");
        System.out.println();
        System.out.println("【已注册的 Agent 端点】");
        System.out.println();
        System.out.println("  Hotel Agent (/hotel):");
        System.out.println("    GET  http://localhost:8080/hotel/ad.json");
        System.out.println("    GET  http://localhost:8080/hotel/interface.json");
        System.out.println("    POST http://localhost:8080/hotel/rpc");
        System.out.println();
        System.out.println("  Shop Agent (/shop):");
        System.out.println("    GET  http://localhost:8080/shop/ad.json");
        System.out.println("    POST http://localhost:8080/shop/rpc");
        System.out.println();
        System.out.println("  Simple Agent (/agent):");
        System.out.println("    GET  http://localhost:8080/agent/ad.json");
        System.out.println("    POST http://localhost:8080/agent/rpc");
        System.out.println();
        System.out.println("────────────────────────────────────────────────────────────");
        System.out.println("【测试流程】在另一个终端执行以下命令:");
        System.out.println("────────────────────────────────────────────────────────────");
        System.out.println();
        System.out.println("1. 查看 Agent 描述:");
        System.out.println("   curl http://localhost:8080/hotel/ad.json | jq");
        System.out.println();
        System.out.println("2. 搜索东京酒店:");
        System.out.println("   curl -X POST http://localhost:8080/hotel/rpc \\");
        System.out.println("     -H \"Content-Type: application/json\" \\");
        System.out.println("     -d '{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"searchHotels\",\"params\":{\"city\":\"Tokyo\"}}'");
        System.out.println();
        System.out.println("3. 预订酒店:");
        System.out.println("   curl -X POST http://localhost:8080/hotel/rpc \\");
        System.out.println("     -H \"Content-Type: application/json\" \\");
        System.out.println("     -d '{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"bookHotel\",\"params\":{\"hotelId\":\"H001\",\"checkIn\":\"2025-02-01\",\"checkOut\":\"2025-02-03\",\"guestName\":\"张三\"}}'");
        System.out.println();
        System.out.println("4. 添加商品到购物车 (Shop Agent):");
        System.out.println("   curl -X POST http://localhost:8080/shop/rpc \\");
        System.out.println("     -H \"Content-Type: application/json\" \\");
        System.out.println("     -d '{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"add_to_cart\",\"params\":{\"product_id\":\"P001\",\"quantity\":2}}'");
        System.out.println();
        System.out.println("5. 查看购物车:");
        System.out.println("   curl -X POST http://localhost:8080/shop/rpc \\");
        System.out.println("     -H \"Content-Type: application/json\" \\");
        System.out.println("     -d '{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"get_cart\",\"params\":{}}'");
        System.out.println();
        System.out.println("────────────────────────────────────────────────────────────");
        System.out.println("按 Ctrl+C 停止服务");
        System.out.println("════════════════════════════════════════════════════════════");
    }
}
