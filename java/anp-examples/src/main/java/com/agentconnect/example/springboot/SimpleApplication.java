/**
 * @program: anp4java
 * @description: 最简 Spring Boot Agent 示例 - 对齐 Python simple_agent.py
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
public class SimpleApplication {
    
    public static void main(String[] args) {
        SpringApplication.run(SimpleApplication.class, args);
        printUsage();
    }
    
    private static void printUsage() {
        System.out.println();
        System.out.println("════════════════════════════════════════════════════════════");
        System.out.println("  🚀 Simple Agent 已启动");
        System.out.println("════════════════════════════════════════════════════════════");
        System.out.println();
        System.out.println("【端点】");
        System.out.println("  GET  http://localhost:8080/agent/ad.json");
        System.out.println("  GET  http://localhost:8080/agent/interface.json");
        System.out.println("  POST http://localhost:8080/agent/rpc");
        System.out.println();
        System.out.println("────────────────────────────────────────────────────────────");
        System.out.println("【测试流程】在另一个终端执行:");
        System.out.println("────────────────────────────────────────────────────────────");
        System.out.println();
        System.out.println("1. 查看 Agent 描述:");
        System.out.println("   curl http://localhost:8080/agent/ad.json | jq");
        System.out.println();
        System.out.println("2. 调用 hello 方法:");
        System.out.println("   curl -X POST http://localhost:8080/agent/rpc \\");
        System.out.println("     -H \"Content-Type: application/json\" \\");
        System.out.println("     -d '{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"hello\",\"params\":{\"name\":\"World\"}}'");
        System.out.println();
        System.out.println("3. 调用 add 方法:");
        System.out.println("   curl -X POST http://localhost:8080/agent/rpc \\");
        System.out.println("     -H \"Content-Type: application/json\" \\");
        System.out.println("     -d '{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"add\",\"params\":{\"a\":10,\"b\":20}}'");
        System.out.println();
        System.out.println("4. 调用 echo 方法:");
        System.out.println("   curl -X POST http://localhost:8080/agent/rpc \\");
        System.out.println("     -H \"Content-Type: application/json\" \\");
        System.out.println("     -d '{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"echo\",\"params\":{\"message\":\"Hello ANP!\"}}'");
        System.out.println();
        System.out.println("────────────────────────────────────────────────────────────");
        System.out.println("按 Ctrl+C 停止服务");
        System.out.println("════════════════════════════════════════════════════════════");
    }
}
