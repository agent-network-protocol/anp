/**
 * @program: anp4java
 * @description: AMAP Crawler 示例 -
 *               演示如何使用 ANPCrawler 发现和调用线上 ANP Agent
 * @author: Ruitao.Zhai
 * @date: 2025-01-29
 */
package com.agentconnect.example.crawler;

import com.agentconnect.crawler.ANPCrawler;
import com.agentconnect.crawler.CrawlResult;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;
import java.util.Map;

/**
 * AMAP Agent Crawler 示例
 * 
 * 功能演示：
 * 1. 获取并打印代理描述文档 (ad.json)
 * 2. 解析 OpenRPC 接口
 * 3. 列出可用工具
 * 4. 调用 JSON-RPC 方法
 * 
 * 对应 Python: examples/python/anp_crawler_examples/amap_crawler_example.py
 */
public class AmapCrawlerExample {
    
    private static final ObjectMapper objectMapper = new ObjectMapper();
    
    private final ANPCrawler crawler;
    private final String agentDescriptionUrl;
    
    public AmapCrawlerExample() {
        String didDocPath = System.getenv("ANP_DID_DOC_PATH");
        String privateKeyPath = System.getenv("ANP_PRIVATE_KEY_PATH");
        
        if (didDocPath == null || privateKeyPath == null) {
            Path projectRoot = findProjectRoot();
            didDocPath = projectRoot.resolve("docs/did_public/public-did-doc.json").toString();
            privateKeyPath = projectRoot.resolve("docs/did_public/public-private-key.pem").toString();
        }
        
        this.crawler = new ANPCrawler(didDocPath, privateKeyPath);
        this.agentDescriptionUrl = "https://agent-connect.ai/mcp/agents/amap/ad.json";
    }
    
    /**
     * 1. 获取并打印代理描述文档
     */
    public CrawlResult fetchAgentDescription() throws Exception {
        System.out.println("\n" + "=".repeat(60));
        System.out.println("步骤 1: 获取 AMAP 代理描述文档");
        System.out.println("=".repeat(60));
        System.out.println("正在获取: " + agentDescriptionUrl);
        
        CrawlResult result = crawler.fetchText(agentDescriptionUrl);
        
        // 检查是否有错误（content 以 "Error:" 开头表示失败）
        String content = result.getContent();
        if (content != null && content.startsWith("Error:")) {
            System.out.println("获取失败: " + content);
            return result;
        }
        
        // 打印代理描述
        Map<String, Object> agentDesc = result.getAgentDescription();
        System.out.println("\n代理描述文档内容:");
        System.out.println(objectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(agentDesc));
        
        System.out.println("\n发现的接口数量: " + result.getToolCount());
        
        return result;
    }
    
    /**
     * 2. 列出所有可用工具
     */
    public List<String> listAvailableTools() {
        System.out.println("\n" + "=".repeat(60));
        System.out.println("步骤 2: 列出可用工具");
        System.out.println("=".repeat(60));
        
        List<String> tools = crawler.listAvailableTools();
        
        if (tools.isEmpty()) {
            System.out.println("未发现任何可用工具");
            return tools;
        }
        
        System.out.println("可用工具 (" + tools.size() + " 个):");
        for (int i = 0; i < tools.size(); i++) {
            String toolName = tools.get(i);
            CrawlResult.MethodInfo info = crawler.getToolInterfaceInfo(toolName);
            String description = info != null ? info.getDescription() : "";
            System.out.printf("  %d. %s: %s%n", i + 1, toolName, description);
        }
        
        return tools;
    }
    
    /**
     * 3. 获取 OpenAI Tools 格式
     */
    public void showOpenAiTools() throws Exception {
        System.out.println("\n" + "=".repeat(60));
        System.out.println("步骤 3: OpenAI Tools 格式");
        System.out.println("=".repeat(60));
        
        List<Map<String, Object>> tools = crawler.getOpenAiTools();
        
        if (tools.isEmpty()) {
            System.out.println("无可用工具");
            return;
        }
        
        System.out.println("OpenAI Tools 格式 (前 3 个):");
        int count = Math.min(3, tools.size());
        for (int i = 0; i < count; i++) {
            System.out.println(objectMapper.writerWithDefaultPrettyPrinter()
                .writeValueAsString(tools.get(i)));
        }
        
        if (tools.size() > 3) {
            System.out.println("... 还有 " + (tools.size() - 3) + " 个工具");
        }
    }
    
    /**
     * 4. 演示工具调用
     */
    public void demonstrateToolCall(String toolName, Map<String, Object> arguments) throws Exception {
        System.out.println("\n" + "=".repeat(60));
        System.out.println("步骤 4: 调用工具 - " + toolName);
        System.out.println("=".repeat(60));
        System.out.println("参数: " + objectMapper.writeValueAsString(arguments));
        
        try {
            Map<String, Object> result = crawler.executeToolCall(toolName, arguments);
            
            System.out.println("\n调用结果:");
            System.out.println(objectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(result));
        } catch (Exception e) {
            System.out.println("调用失败: " + e.getMessage());
        }
    }
    
    /**
     * 5. 演示直接 JSON-RPC 调用
     */
    public void demonstrateJsonRpcCall() throws Exception {
        System.out.println("\n" + "=".repeat(60));
        System.out.println("步骤 5: 直接 JSON-RPC 调用 - 骑行路径规划");
        System.out.println("=".repeat(60));
        
        String endpoint = "https://agent-connect.ai/mcp/agents/tools/amap";
        String method = "maps_direction_bicycling";
        Map<String, Object> params = Map.of(
            "origin", "116.481028,39.989643",      // 天安门
            "destination", "116.434446,39.90816"   // 北京西站
        );
        
        System.out.println("端点: " + endpoint);
        System.out.println("方法: " + method);
        System.out.println("参数:");
        System.out.println("  出发点 (origin): " + params.get("origin") + " [天安门]");
        System.out.println("  目的地 (destination): " + params.get("destination") + " [北京西站]");
        
        try {
            Map<String, Object> result = crawler.executeJsonRpc(endpoint, method, params);
            
            System.out.println("\nJSON-RPC 调用结果:");
            System.out.println(objectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(result));
        } catch (Exception e) {
            System.out.println("调用失败: " + e.getMessage());
        }
    }
    
    /**
     * 6. 显示会话统计
     */
    public void showSessionStats() {
        System.out.println("\n" + "=".repeat(60));
        System.out.println("会话统计");
        System.out.println("=".repeat(60));
        System.out.println("访问的 URL 数量: " + crawler.getVisitedUrls().size());
        System.out.println("缓存条目数量: " + crawler.getCacheSize());
        System.out.println("访问的 URL 列表:");
        for (String url : crawler.getVisitedUrls()) {
            System.out.println("  - " + url);
        }
    }
    
    /**
     * 运行完整示例
     */
    public void runExample() {
        try {
            System.out.println("ANPCrawler AMAP 服务示例");
            System.out.println("=".repeat(60));
            
            CrawlResult result = fetchAgentDescription();
            
            String content = result.getContent();
            if (content != null && content.startsWith("Error:")) {
                System.out.println("\n注意: AMAP 服务可能暂时不可用 (502 错误)");
                System.out.println("可以尝试其他 Agent，如 Navigation:");
                System.out.println("  https://agent-search.ai/agents/navigation/ad.json");
                return;
            }
            
            // 2. 列出可用工具
            List<String> tools = listAvailableTools();
            
            // 3. 显示 OpenAI Tools 格式
            showOpenAiTools();
            
            // 4. 如果有工具，演示调用
            if (!tools.isEmpty()) {
                String firstTool = tools.get(0);
                Map<String, Object> sampleArgs = Map.of(
                    "query", "北京天安门",
                    "city", "北京"
                );
                demonstrateToolCall(firstTool, sampleArgs);
            }
            
            // 5. 演示直接 JSON-RPC 调用
            demonstrateJsonRpcCall();
            
            // 6. 显示会话统计
            showSessionStats();
            
        } catch (Exception e) {
            System.err.println("示例运行失败: " + e.getMessage());
            e.printStackTrace();
        }
    }
    
    private static Path findProjectRoot() {
        Path current = Paths.get(System.getProperty("user.dir"));
        for (int i = 0; i < 5; i++) {
            if (current.resolve("docs/did_public").toFile().exists()) {
                return current;
            }
            current = current.getParent();
            if (current == null) break;
        }
        throw new RuntimeException("找不到项目根目录 (需要 docs/did_public 目录)");
    }
    
    public static void main(String[] args) {
        System.out.println("=".repeat(60));
        System.out.println("ANPCrawler AMAP 服务示例");
        System.out.println("对应 Python: amap_crawler_example.py");
        System.out.println("=".repeat(60));
        
        AmapCrawlerExample example = new AmapCrawlerExample();
        example.runExample();
    }
}
