/**
 * @program: anp4java
 * @description: AP2 支付协议概念示例
 * @author: Ruitao.Zhai
 * @date: 2025-01-29
 **/
package com.agentconnect.example.advanced;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication(scanBasePackages = {
    "com.agentconnect.example.advanced",
    "com.agentconnect.spring"
})
public class AdvancedShopApplication {
    
    public static void main(String[] args) {
        System.out.println();
        System.out.println("=".repeat(60));
        System.out.println("正在启动高级商店 Agent (Spring Boot)");
        System.out.println("=".repeat(60));
        System.out.println();
        System.out.println("本示例演示：");
        System.out.println("  - 内容模式接口（嵌入在 interface.json 中）");
        System.out.println("  - 链接模式接口（单独的接口文件）");
        System.out.println("  - URL 模式信息（托管端点）");
        System.out.println("  - 内容模式信息（嵌入在 ad.json 中）");
        System.out.println("  - 上下文和会话管理");
        System.out.println();
        
        SpringApplication.run(AdvancedShopApplication.class, args);
        
        System.out.println();
        System.out.println("可用端点：");
        System.out.println("  GET  http://localhost:8080/advanced-shop/ad.json");
        System.out.println("  GET  http://localhost:8080/advanced-shop/interface.json");
        System.out.println("  GET  http://localhost:8080/advanced-shop/interface/checkout.json");
        System.out.println("  GET  http://localhost:8080/advanced-shop/products/featured.json");
        System.out.println("  POST http://localhost:8080/advanced-shop/rpc");
        System.out.println();
    }
}
