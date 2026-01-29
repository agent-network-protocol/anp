/**
 * @program: anp4java
 * @description: LLM 驱动的智能 ANP Agent 客户端
 * @author: Ruitao.Zhai
 * @date: 2025-01-29
 */
package com.agentconnect.example.online;

import com.agentconnect.crawler.ANPCrawler;
import com.agentconnect.crawler.CrawlResult;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Duration;
import java.util.*;

public class SmartAgentClient {
    
    private static final ObjectMapper objectMapper = new ObjectMapper();
    
    private final ANPCrawler crawler;
    private final HttpClient httpClient;
    private final String llmApiKey;
    private final String llmBaseUrl;
    private final String llmModel;
    
    private String currentAgentUrl;
    private Map<String, Object> currentAgentDesc;
    private List<Map<String, Object>> availableTools;
    
    public SmartAgentClient() {
        this.llmApiKey = getEnvOrDefault("OPENAI_API_KEY", null);
        this.llmBaseUrl = getEnvOrDefault("OPENAI_BASE_URL", "https://api.openai.com/v1");
        this.llmModel = getEnvOrDefault("OPENAI_MODEL", "gpt-3.5-turbo");
        
        String didDocPath = getEnvOrDefault("ANP_DID_DOC_PATH", null);
        String privateKeyPath = getEnvOrDefault("ANP_PRIVATE_KEY_PATH", null);
        
        if (didDocPath == null || privateKeyPath == null) {
            Path projectRoot = findProjectRoot();
            didDocPath = projectRoot.resolve("docs/did_public/public-did-doc.json").toString();
            privateKeyPath = projectRoot.resolve("docs/did_public/public-private-key.pem").toString();
        }
        
        this.crawler = new ANPCrawler(didDocPath, privateKeyPath);
        this.httpClient = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(30))
            .build();
    }
    
    public void connectAgent(String adUrl) throws Exception {
        System.out.println("\n连接 Agent: " + adUrl);
        
        CrawlResult result = crawler.fetchText(adUrl);
        this.currentAgentUrl = adUrl;
        this.currentAgentDesc = result.getAgentDescription();
        this.availableTools = crawler.getOpenAiTools();
        
        System.out.println("✓ 已连接: " + currentAgentDesc.get("name"));
        System.out.println("  DID: " + currentAgentDesc.get("did"));
        System.out.println("  发现 " + availableTools.size() + " 个可调用方法");
        
        if (!availableTools.isEmpty()) {
            System.out.println("\n可用方法:");
            for (String tool : crawler.listAvailableTools()) {
                CrawlResult.MethodInfo info = crawler.getToolInterfaceInfo(tool);
                System.out.println("  - " + tool + ": " + (info != null ? info.getDescription() : ""));
            }
        }
    }
    
    public String chat(String userMessage) throws Exception {
        if (llmApiKey == null || llmApiKey.isEmpty()) {
            return "错误: 未配置 OPENAI_API_KEY 环境变量";
        }
        
        System.out.println("\n" + "=".repeat(50));
        System.out.println("用户: " + userMessage);
        System.out.println("=".repeat(50));
        
        String systemPrompt = buildSystemPrompt();
        
        List<Map<String, Object>> messages = new ArrayList<>();
        messages.add(Map.of("role", "system", "content", systemPrompt));
        messages.add(Map.of("role", "user", "content", userMessage));
        
        Map<String, Object> requestBody = new LinkedHashMap<>();
        requestBody.put("model", llmModel);
        requestBody.put("messages", messages);
        
        if (!availableTools.isEmpty()) {
            requestBody.put("tools", availableTools);
            requestBody.put("tool_choice", "auto");
        }
        
        String llmResponse = callLLM(requestBody);
        Map<String, Object> responseJson = objectMapper.readValue(llmResponse, new TypeReference<>() {});
        
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> choices = (List<Map<String, Object>>) responseJson.get("choices");
        if (choices == null || choices.isEmpty()) {
            return "LLM 无响应";
        }
        
        @SuppressWarnings("unchecked")
        Map<String, Object> message = (Map<String, Object>) choices.get(0).get("message");
        
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> toolCalls = (List<Map<String, Object>>) message.get("tool_calls");
        
        if (toolCalls != null && !toolCalls.isEmpty()) {
            return handleToolCalls(userMessage, toolCalls, messages);
        }
        
        String content = (String) message.get("content");
        System.out.println("\n助手: " + content);
        return content;
    }
    
    private String handleToolCalls(String userMessage, List<Map<String, Object>> toolCalls, 
                                   List<Map<String, Object>> messages) throws Exception {
        StringBuilder results = new StringBuilder();
        
        for (Map<String, Object> toolCall : toolCalls) {
            @SuppressWarnings("unchecked")
            Map<String, Object> function = (Map<String, Object>) toolCall.get("function");
            String functionName = (String) function.get("name");
            String argsJson = (String) function.get("arguments");
            
            System.out.println("\n[调用 Agent 方法: " + functionName + "]");
            System.out.println("参数: " + argsJson);
            
            try {
                Map<String, Object> params = objectMapper.readValue(argsJson, new TypeReference<>() {});
                Map<String, Object> result = crawler.executeToolCall(functionName, params);
                
                String resultJson = objectMapper.writeValueAsString(result);
                System.out.println("结果: " + resultJson);
                
                results.append("方法 ").append(functionName).append(" 返回:\n").append(resultJson).append("\n\n");
                
                messages.add(Map.of(
                    "role", "assistant",
                    "content", "",
                    "tool_calls", List.of(toolCall)
                ));
                messages.add(Map.of(
                    "role", "tool",
                    "tool_call_id", toolCall.get("id"),
                    "content", resultJson
                ));
            } catch (Exception e) {
                System.out.println("调用失败: " + e.getMessage());
                results.append("方法 ").append(functionName).append(" 失败: ").append(e.getMessage()).append("\n\n");
            }
        }
        
        messages.add(Map.of("role", "user", "content", "请根据上述工具调用结果，用自然语言回答用户的问题。"));
        
        Map<String, Object> summaryRequest = new LinkedHashMap<>();
        summaryRequest.put("model", llmModel);
        summaryRequest.put("messages", messages);
        
        String summaryResponse = callLLM(summaryRequest);
        Map<String, Object> summaryJson = objectMapper.readValue(summaryResponse, new TypeReference<>() {});
        
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> summaryChoices = (List<Map<String, Object>>) summaryJson.get("choices");
        if (summaryChoices != null && !summaryChoices.isEmpty()) {
            @SuppressWarnings("unchecked")
            Map<String, Object> summaryMessage = (Map<String, Object>) summaryChoices.get(0).get("message");
            String finalAnswer = (String) summaryMessage.get("content");
            System.out.println("\n助手: " + finalAnswer);
            return finalAnswer;
        }
        
        return results.toString();
    }
    
    private String buildSystemPrompt() {
        StringBuilder sb = new StringBuilder();
        sb.append("你是一个智能助手，可以通过 ANP 协议调用远程 Agent 获取信息。\n\n");
        
        if (currentAgentDesc != null) {
            sb.append("当前连接的 Agent:\n");
            sb.append("- 名称: ").append(currentAgentDesc.get("name")).append("\n");
            sb.append("- 描述: ").append(currentAgentDesc.get("description")).append("\n\n");
            
            @SuppressWarnings("unchecked")
            List<Map<String, Object>> mainAgents = (List<Map<String, Object>>) currentAgentDesc.get("mainAgentList");
            if (mainAgents != null && !mainAgents.isEmpty()) {
                sb.append("已注册的 Agent 列表:\n");
                for (Map<String, Object> agent : mainAgents) {
                    sb.append("- ").append(agent.get("name")).append(": ").append(agent.get("description")).append("\n");
                }
                sb.append("\n");
            }
        }
        
        sb.append("当用户询问信息时，请调用合适的工具获取数据，然后用自然语言回答。");
        return sb.toString();
    }
    
    private String callLLM(Map<String, Object> requestBody) throws Exception {
        String jsonBody = objectMapper.writeValueAsString(requestBody);
        String endpoint = llmBaseUrl + "/chat/completions";
        
        HttpRequest request = HttpRequest.newBuilder()
            .uri(URI.create(endpoint))
            .header("Content-Type", "application/json")
            .header("Authorization", "Bearer " + llmApiKey)
            .POST(HttpRequest.BodyPublishers.ofString(jsonBody))
            .timeout(Duration.ofSeconds(60))
            .build();
        
        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        
        if (response.statusCode() != 200) {
            throw new RuntimeException("LLM API 错误: " + response.statusCode() + " - " + response.body());
        }
        
        return response.body();
    }
    
    private static String getEnvOrDefault(String key, String defaultValue) {
        String value = System.getenv(key);
        return (value != null && !value.isEmpty()) ? value : defaultValue;
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
        throw new RuntimeException("找不到项目根目录");
    }
    
    public static void main(String[] args) {
        System.out.println("=".repeat(60));
        System.out.println("智能 ANP Agent 客户端");
        System.out.println("=".repeat(60));
        System.out.println();
        System.out.println("环境变量配置:");
        System.out.println("  OPENAI_API_KEY  = " + maskKey(System.getenv("OPENAI_API_KEY")));
        System.out.println("  OPENAI_BASE_URL = " + getEnvOrDefault("OPENAI_BASE_URL", "https://api.openai.com/v1"));
        System.out.println("  OPENAI_MODEL    = " + getEnvOrDefault("OPENAI_MODEL", "gpt-3.5-turbo"));
        System.out.println();
        
        String apiKey = System.getenv("OPENAI_API_KEY");
        if (apiKey == null || apiKey.isEmpty()) {
            System.out.println("错误: 请设置 OPENAI_API_KEY 环境变量");
            System.out.println();
            System.out.println("示例:");
            System.out.println("  export OPENAI_API_KEY=your-key");
            System.out.println("  export OPENAI_BASE_URL=https://your-api.com/v1");
            System.out.println("  export OPENAI_MODEL=gpt-3.5-turbo");
            System.out.println("  mvn exec:java -Dexec.mainClass=\"com.agentconnect.example.online.SmartAgentClient\"");
            return;
        }
        
        try {
            SmartAgentClient client = new SmartAgentClient();
            
            String defaultAgentUrl = "https://agent-connect.ai/mcp/agents/amap/ad.json";
            System.out.println("连接默认 Agent: " + defaultAgentUrl);
            client.connectAgent(defaultAgentUrl);
            
            Scanner scanner = new Scanner(System.in);
            System.out.println("\n开始对话 (输入 'quit' 退出, 'connect <url>' 切换 Agent):\n");
            
            while (true) {
                System.out.print("你: ");
                if (!scanner.hasNextLine()) break;
                
                String input = scanner.nextLine().trim();
                if (input.isEmpty()) continue;
                
                if ("quit".equalsIgnoreCase(input)) {
                    System.out.println("再见！");
                    break;
                }
                
                if (input.toLowerCase().startsWith("connect ")) {
                    String url = input.substring(8).trim();
                    try {
                        client.connectAgent(url);
                    } catch (Exception e) {
                        System.out.println("连接失败: " + e.getMessage());
                    }
                    continue;
                }
                
                try {
                    client.chat(input);
                } catch (Exception e) {
                    System.out.println("错误: " + e.getMessage());
                }
            }
            
            scanner.close();
        } catch (Exception e) {
            System.err.println("启动失败: " + e.getMessage());
            e.printStackTrace();
        }
    }
    
    private static String maskKey(String key) {
        if (key == null || key.length() < 8) return "(未设置)";
        return key.substring(0, 4) + "****" + key.substring(key.length() - 4);
    }
}
