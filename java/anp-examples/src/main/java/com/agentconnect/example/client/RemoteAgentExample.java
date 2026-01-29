/**
 * @program: anp4java
 * @description: RemoteAgent 客户端示例
 * @author: Ruitao.Zhai
 * @date: 2025-01-28
 **/
package com.agentconnect.example.client;

import com.agentconnect.authentication.DIDWbaAuthHeader;
import com.agentconnect.client.RemoteAgent;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;
import java.util.Map;


public class RemoteAgentExample {
    /**
     * RemoteAgent 客户端示例
     *
     * 本示例演示了代理风格的客户端模式：
     * 1. 从 ad.json URL 发现远程 Agent
     * 2. 检查可用方法
     * 3. 调用远程 Agent 上的方法
     * 4. 获取 OpenAI Tools 格式以用于 LLM 集成
     */
    private static final ObjectMapper objectMapper = new ObjectMapper();
    
    // 线上 Navigation Agent (稳定可用)
    private static final String DEFAULT_AD_URL = "https://agent-search.ai/agents/navigation/ad.json";
    
    public static void main(String[] args) {
        try {
            System.out.println();
            System.out.println("=".repeat(60));
            System.out.println("RemoteAgent 客户端示例");
            System.out.println("=".repeat(60));
            System.out.println();
            
            String adUrl = args.length > 0 ? args[0] : DEFAULT_AD_URL;
            
            System.out.println("目标 Agent：" + adUrl);
            System.out.println();
            
            String didDocPathStr = System.getenv("ANP_DID_DOC_PATH");
            String privateKeyPathStr = System.getenv("ANP_PRIVATE_KEY_PATH");
            
            Path didDocPath = didDocPathStr != null ? Paths.get(didDocPathStr) : Paths.get("docs/did_public/public-did-doc.json");
            Path privateKeyPath = privateKeyPathStr != null ? Paths.get(privateKeyPathStr) : Paths.get("docs/did_public/public-private-key.pem");
            
            DIDWbaAuthHeader auth = null;
            if (Files.exists(didDocPath) && Files.exists(privateKeyPath)) {
                System.out.println("使用 DID 认证：");
                System.out.println("  DID 文档：" + didDocPath);
                System.out.println("  私钥：" + privateKeyPath);
                auth = new DIDWbaAuthHeader(didDocPath.toString(), privateKeyPath.toString());
            } else {
                System.out.println("未找到 DID 凭据，将不使用认证继续。");
                System.out.println("（对于本地测试，这通常没问题）");
            }
            System.out.println();
            
            // 【步骤 1】发现远程 Agent
            System.out.println("【步骤 1】发现远程 Agent");
            System.out.println("-".repeat(40));
            
            RemoteAgent agent;
            try {
                agent = RemoteAgent.discover(adUrl, auth);
            } catch (Exception e) {
                System.err.println("无法发现 Agent！");
                System.err.println("错误：" + e.getMessage());
                System.err.println();
                System.err.println("请确保服务器正在运行：");
                System.err.println("  mvn exec:java -pl anp-examples \\");
                System.err.println("    -Dexec.mainClass=\"com.agentconnect.example.local.HotelServer\"");
                return;
            }
            
            System.out.println("Agent 发现成功！");
            System.out.println("  名称：" + agent.getName());
            System.out.println("  描述：" + agent.getDescription());
            System.out.println("  URL：" + agent.getUrl());
            System.out.println();
            
            // 【步骤 2】列出可用方法
            System.out.println("【步骤 2】可用方法");
            System.out.println("-".repeat(40));
            
            List<String> methodNames = agent.getMethodNames();
            System.out.println("找到 " + methodNames.size() + " 个方法：");
            
            for (RemoteAgent.Method method : agent.getMethods()) {
                System.out.println("  - " + method.getName());
                System.out.println("    描述：" + method.getDescription());
                System.out.println("    RPC URL：" + method.getRpcUrl());
            }
            System.out.println();
            
            // 【步骤 3】调用方法
            System.out.println("【步骤 3】调用方法");
            System.out.println("-".repeat(40));
            
            // 调用 search_agents (Navigation Agent 的方法)
            if (methodNames.contains("search_agents")) {
                System.out.println("正在调用 search_agents(query='酒店', limit=5)...");
                Object result = agent.call("search_agents", Map.of("query", "酒店", "limit", 5));
                System.out.println("结果：" + prettyJson(result));
                System.out.println();
            }
            
            // 如果是本地 Hotel Agent，尝试调用其方法
            if (methodNames.contains("searchHotels")) {
                System.out.println("正在调用 searchHotels(city='Tokyo')...");
                Object result = agent.call("searchHotels", Map.of("city", "Tokyo"));
                System.out.println("结果：" + prettyJson(result));
                System.out.println();
            }
            
            // 【步骤 4】获取 OpenAI Tools 格式
            System.out.println("【步骤 4】OpenAI Tools 格式（用于 LLM 集成）");
            System.out.println("-".repeat(40));
            
            List<Map<String, Object>> tools = agent.getTools();
            System.out.println("生成了 " + tools.size() + " 个工具定义：");
            System.out.println(prettyJson(tools));
            System.out.println();
            
            // 总结
            System.out.println("=".repeat(60));
            System.out.println("RemoteAgent 示例完成！");
            System.out.println();
            System.out.println("要点：");
            System.out.println("  1. 使用 RemoteAgent.discover() 连接到任何 ANP Agent");
            System.out.println("  2. 使用 agent.call() 调用远程方法");
            System.out.println("  3. 使用 agent.getTools() 进行 LLM 集成");
            System.out.println("=".repeat(60));
            
        } catch (Exception e) {
            System.err.println("错误：" + e.getMessage());
            e.printStackTrace();
        }
    }
    
    private static String prettyJson(Object obj) {
        try {
            return objectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(obj);
        } catch (Exception e) {
            return obj.toString();
        }
    }
}
