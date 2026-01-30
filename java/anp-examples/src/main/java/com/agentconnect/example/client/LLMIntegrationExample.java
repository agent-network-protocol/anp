/**
 * @program: anp4java
 * @description: LLM 集成客户端示例
 * @author: Ruitao.Zhai
 * @date: 2025-01-28
 **/
package com.agentconnect.example.client;

import com.agentconnect.crawler.ANPCrawler;
import com.agentconnect.crawler.CrawlResult;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.util.List;
import java.util.Map;

public class LLMIntegrationExample {
    /**
     * LLM 集成示例
     *
     * 本示例演示如何：
     * 1. 发现 ANP Agent
     * 2. 将其方法转换为 OpenAI Tools 格式
     * 3. 将工具与 LLM 一起使用（模拟）
     * 4. 执行工具调用
     *
     * 在实际应用中，您将：
     * 1. 将工具传递给您的 LLM（OpenAI, Anthropic 等）
     * 2. 让 LLM 决定调用哪个工具
     * 3. 使用 ANPCrawler 执行工具调用
     * 4. 将结果返回给 LLM
     */
    private static final ObjectMapper objectMapper = new ObjectMapper();
    
    // 线上 Navigation Agent (稳定可用)
    private static final String NAVIGATION_AGENT_URL = "https://agent-search.ai/agents/navigation/ad.json";
    
    public static void main(String[] args) {
        try {
            System.out.println();
            System.out.println("=".repeat(60));
            System.out.println("LLM 集成示例");
            System.out.println("=".repeat(60));
            System.out.println();
            
            String agentUrl = args.length > 0 ? args[0] : NAVIGATION_AGENT_URL;
            
            System.out.println("目标 Agent：" + agentUrl);
            System.out.println();
            
            // 创建爬虫（演示不需要 DID 认证）
            ANPCrawler crawler = new ANPCrawler();
            
            // 【步骤 1】抓取并解析 Agent 描述
            System.out.println("【步骤 1】发现 Agent");
            System.out.println("-".repeat(40));
            
            CrawlResult result;
            try {
                result = crawler.fetchText(agentUrl);
            } catch (Exception e) {
                System.err.println("无法连接到 Agent：" + e.getMessage());
                System.err.println();
                System.err.println("如果使用本地 Agent，请确保服务器正在运行：");
                System.err.println("  mvn exec:java -pl anp-examples \\");
                System.err.println("    -Dexec.mainClass=\"com.agentconnect.example.local.HotelServer\"");
                return;
            }
            
            Map<String, Object> agentDesc = result.getAgentDescription();
            System.out.println("Agent：" + agentDesc.get("name"));
            System.out.println("DID：" + agentDesc.get("did"));
            System.out.println();
            
            // 【步骤 2】获取 OpenAI Tools 格式
            System.out.println("【步骤 2】转换为 OpenAI Tools 格式");
            System.out.println("-".repeat(40));
            
            List<Map<String, Object>> tools = crawler.getOpenAiTools();
            List<String> toolNames = crawler.listAvailableTools();
            
            System.out.println("找到 " + toolNames.size() + " 个工具：");
            for (String name : toolNames) {
                CrawlResult.MethodInfo info = crawler.getToolInterfaceInfo(name);
                System.out.println("  - " + name + "：" + (info != null ? info.getDescription() : ""));
            }
            System.out.println();
            
            // 打印完整的工具 JSON（给 LLM 用）
            System.out.println("OpenAI Tools JSON（将此传递给您的 LLM）：");
            System.out.println(prettyJson(tools));
            System.out.println();
            
            // 【步骤 3】模拟 LLM 工具调用
            System.out.println("【步骤 3】模拟 LLM 工具调用");
            System.out.println("-".repeat(40));
            System.out.println();
            System.out.println("在实际应用中，您将：");
            System.out.println("  1. 发送用户消息 + 工具给 LLM");
            System.out.println("  2. LLM 响应一个 tool_call");
            System.out.println("  3. 使用 crawler.executeToolCall() 执行工具调用");
            System.out.println("  4. 将结果返回给 LLM");
            System.out.println();
            
            if (toolNames.contains("search_agents")) {
                System.out.println("模拟的 LLM tool_call：");
                System.out.println("  function: search_agents");
                System.out.println("  arguments: {\"query\": \"酒店\", \"limit\": 5}");
                System.out.println();
                
                System.out.println("正在执行工具调用...");
                Map<String, Object> toolResult = crawler.executeToolCall("search_agents", Map.of("query", "酒店", "limit", 5));
                
                System.out.println("工具结果（将此返回给 LLM）：");
                System.out.println(prettyJson(toolResult));
                System.out.println();
            } else if (toolNames.contains("searchHotels")) {
                System.out.println("模拟的 LLM tool_call：");
                System.out.println("  function: searchHotels");
                System.out.println("  arguments: {\"city\": \"Tokyo\"}");
                System.out.println();
                
                System.out.println("正在执行工具调用...");
                Map<String, Object> toolResult = crawler.executeToolCall("searchHotels", Map.of("city", "Tokyo"));
                
                System.out.println("工具结果（将此返回给 LLM）：");
                System.out.println(prettyJson(toolResult));
                System.out.println();
            }
            
            // 【步骤 4】使用模式
            System.out.println("【步骤 4】完整使用模式");
            System.out.println("-".repeat(40));
            System.out.println();
            System.out.println("```java");
            System.out.println("// 1. Initialize crawler");
            System.out.println("ANPCrawler crawler = new ANPCrawler(didDocPath, keyPath);");
            System.out.println("crawler.fetchText(agentUrl);");
            System.out.println();
            System.out.println("// 2. Get tools for LLM");
            System.out.println("List<Map<String, Object>> tools = crawler.getOpenAiTools();");
            System.out.println();
            System.out.println("// 3. Send to LLM (OpenAI example)");
            System.out.println("ChatCompletionRequest request = ChatCompletionRequest.builder()");
            System.out.println("    .model(\"gpt-4\")");
            System.out.println("    .messages(messages)");
            System.out.println("    .tools(tools)");
            System.out.println("    .build();");
            System.out.println();
            System.out.println("// 4. Execute LLM's tool call");
            System.out.println("ToolCall toolCall = response.getToolCalls().get(0);");
            System.out.println("Map<String, Object> result = crawler.executeToolCall(");
            System.out.println("    toolCall.getFunction().getName(),");
            System.out.println("    parseJson(toolCall.getFunction().getArguments())");
            System.out.println(");");
            System.out.println("```");
            System.out.println();
            
            // 总结
            System.out.println("=".repeat(60));
            System.out.println("LLM 集成示例完成！");
            System.out.println();
            System.out.println("核心类：");
            System.out.println("  - ANPCrawler：发现 Agent 并转换为工具");
            System.out.println("  - crawler.getOpenAiTools()：返回 LLM 就绪的工具定义");
            System.out.println("  - crawler.executeToolCall()：执行 LLM 工具调用");
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
