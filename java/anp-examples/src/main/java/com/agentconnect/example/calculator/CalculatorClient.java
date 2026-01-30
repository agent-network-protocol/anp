/**
 * @program: anp4java
 * @author: Ruitao.Zhai
 * @date: 2025-01-29
 */
package com.agentconnect.example.calculator;

import com.agentconnect.crawler.ANPCrawler;
import com.agentconnect.crawler.CrawlResult;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.Map;

/**
 * Calculator Agent Client - Aligned with Python OpenANP minimal_client.py
 */
public class CalculatorClient {
    
    private static final Logger log = LoggerFactory.getLogger(CalculatorClient.class);
    private static final ObjectMapper objectMapper = new ObjectMapper();
    
    private static final String AGENT_URL = "http://localhost:8000/agent/ad.json";
    
    public static void main(String[] args) {
        try {
            System.out.println();
            System.out.println("=".repeat(60));
            System.out.println("Calculator Agent Client");
            System.out.println("=".repeat(60));
            System.out.println();
            
            ANPCrawler crawler = new ANPCrawler();
            
            System.out.println("Discovering agent...");
            CrawlResult result = crawler.fetchText(AGENT_URL);
            Map<String, Object> agentDesc = result.getAgentDescription();
            
            if (agentDesc == null || agentDesc.isEmpty()) {
                System.out.println("Connection failed!");
                System.out.println("\nPlease start the server first:");
                System.out.println("  mvn exec:java -pl anp-examples \\");
                System.out.println("    -Dexec.mainClass=\"com.agentconnect.example.calculator.CalculatorServer\"");
                return;
            }
            
            System.out.println("Connected: " + agentDesc.get("name"));
            System.out.println();
            
            List<String> tools = crawler.listAvailableTools();
            System.out.println("Available methods: " + tools);
            System.out.println();
            
            System.out.println("Testing methods:");
            System.out.println("-".repeat(40));
            
            Map<String, Object> addResult = crawler.executeToolCall("add", Map.of("a", 10, "b", 20));
            Object addValue = extractResult(addResult);
            System.out.println("10 + 20 = " + addValue);
            
            Map<String, Object> multiplyResult = crawler.executeToolCall("multiply", Map.of("a", 6, "b", 7));
            Object multiplyValue = extractResult(multiplyResult);
            System.out.println("6 × 7 = " + multiplyValue);
            
            Map<String, Object> subtractResult = crawler.executeToolCall("subtract", Map.of("a", 100, "b", 42));
            Object subtractValue = extractResult(subtractResult);
            System.out.println("100 - 42 = " + subtractValue);
            
            Map<String, Object> divideResult = crawler.executeToolCall("divide", Map.of("a", 22.0, "b", 7.0));
            Object divideValue = extractResult(divideResult);
            System.out.println("22 / 7 = " + divideValue);
            
            System.out.println();
            System.out.println("=".repeat(60));
            System.out.println("Demo completed!");
            System.out.println("=".repeat(60));
            
        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
            System.err.println();
            System.err.println("Please ensure the server is running:");
            System.err.println("mvn exec:java -pl anp-examples \\");
            System.err.println("  -Dexec.mainClass=\"com.agentconnect.example.calculator.CalculatorServer\"");
            e.printStackTrace();
        }
    }
    
    @SuppressWarnings("unchecked")
    private static Object extractResult(Map<String, Object> rpcResponse) {
        if (rpcResponse.containsKey("result")) {
            return rpcResponse.get("result");
        }
        Map<String, Object> response = (Map<String, Object>) rpcResponse.get("response");
        if (response != null && response.containsKey("result")) {
            return response.get("result");
        }
        return rpcResponse;
    }
}
