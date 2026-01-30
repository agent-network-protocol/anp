/**
 * @program: anp4java
 * @author: Ruitao.Zhai
 * @date: 2025-01-29
 */
package com.agentconnect.crawler;

import com.agentconnect.client.ANPClient;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.URI;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * ANP Crawler for discovering and interacting with ANP agents.
 * 
 * This is a crawler-style SDK that fetches and parses ANP documents,
 * extracts callable interfaces, and converts them to OpenAI Tools format.
 * 
 * Unlike RemoteAgent (proxy-style), ANPCrawler is procedural:
 * - RemoteAgent: agent.search(query) - feels like local method calls
 * - ANPCrawler: crawler.executeToolCall("search", params) - explicit tool execution
 * 
 * Example:
 *     ANPCrawler crawler = new ANPCrawler(
 *         "/path/to/did-doc.json",
 *         "/path/to/private-key.pem"
 *     );
 *     
 *     // Fetch and parse agent description
 *     CrawlResult result = crawler.fetchText("https://example.com/ad.json");
 *     
 *     // Get OpenAI Tools format
 *     List<Map<String, Object>> tools = crawler.getOpenAiTools();
 *     
 *     // Execute a tool call
 *     Map<String, Object> response = crawler.executeToolCall("search", Map.of("query", "Tokyo"));
 *     
 *     // Or call JSON-RPC directly
 *     Map<String, Object> response = crawler.executeJsonRpc(
 *         "https://example.com/rpc",
 *         "search",
 *         Map.of("query", "Tokyo")
 *     );
 */
public class ANPCrawler {
    
    private static final Logger logger = LoggerFactory.getLogger(ANPCrawler.class);
    private static final ObjectMapper objectMapper = new ObjectMapper();
    
    private final String didDocumentPath;
    private final String privateKeyPath;
    private final boolean cacheEnabled;
    
    private final ANPClient client;
    private final Set<String> visitedUrls;
    private final Map<String, CrawlResult> cache;
    private final Map<String, CrawlResult.MethodInfo> toolInterfaces;
    
    private String agentDescriptionUri;
    
    /**
     * Create an ANP crawler without DID authentication.
     * Useful for local testing or public agents that don't require auth.
     */
    public ANPCrawler() {
        this.didDocumentPath = null;
        this.privateKeyPath = null;
        this.cacheEnabled = true;
        
        this.client = new ANPClient();
        this.visitedUrls = ConcurrentHashMap.newKeySet();
        this.cache = new ConcurrentHashMap<>();
        this.toolInterfaces = new ConcurrentHashMap<>();
        
        logger.info("ANPCrawler initialized without DID authentication");
    }
    
    /**
     * Create an ANP crawler with DID authentication.
     * 
     * @param didDocumentPath Path to the DID document JSON file
     * @param privateKeyPath Path to the private key PEM file
     */
    public ANPCrawler(String didDocumentPath, String privateKeyPath) {
        this(didDocumentPath, privateKeyPath, true);
    }
    
    /**
     * Create an ANP crawler with optional caching.
     * 
     * @param didDocumentPath Path to the DID document JSON file
     * @param privateKeyPath Path to the private key PEM file
     * @param cacheEnabled Whether to enable URL caching
     */
    public ANPCrawler(String didDocumentPath, String privateKeyPath, boolean cacheEnabled) {
        this.didDocumentPath = Objects.requireNonNull(didDocumentPath, "didDocumentPath cannot be null");
        this.privateKeyPath = Objects.requireNonNull(privateKeyPath, "privateKeyPath cannot be null");
        this.cacheEnabled = cacheEnabled;
        
        this.client = new ANPClient(didDocumentPath, privateKeyPath);
        this.visitedUrls = ConcurrentHashMap.newKeySet();
        this.cache = new ConcurrentHashMap<>();
        this.toolInterfaces = new ConcurrentHashMap<>();
        
        logger.info("ANPCrawler initialized with DID document: {}", didDocumentPath);
    }
    
    /**
     * Fetch text content from a URL and parse interfaces.
     * 
     * This method handles:
     * - Agent Description files (ad.json)
     * - Interface definition files (OpenRPC format)
     * 
     * @param url URL to fetch content from
     * @return CrawlResult containing content and discovered tools
     * @throws IOException If the fetch fails
     */
    public CrawlResult fetchText(String url) throws IOException, InterruptedException {
        logger.info("Fetching text content from: {}", url);
        
        // Set agent description URI on first fetch
        if (agentDescriptionUri == null) {
            agentDescriptionUri = removeUrlParams(url);
        }
        
        // Check cache first
        if (cacheEnabled) {
            CrawlResult cached = cache.get(url);
            if (cached != null) {
                logger.info("Using cached result for: {}", url);
                return cached;
            }
        }
        
        try {
            // Add to visited URLs
            visitedUrls.add(url);
            
            // Fetch content
            Map<String, Object> response = client.fetch(url);
            String rawContent = objectMapper.writeValueAsString(response);
            
            // Build result
            CrawlResult.Builder resultBuilder = CrawlResult.builder()
                .content(rawContent)
                .agentDescriptionUri(agentDescriptionUri)
                .contentUri(removeUrlParams(url))
                .agentDescription(response);
            
            // Parse interfaces from ad.json
            parseInterfaces(response, resultBuilder);
            
            CrawlResult result = resultBuilder.build();
            
            // Cache the result
            if (cacheEnabled) {
                cache.put(url, result);
            }
            
            logger.info("Successfully fetched from: {}, found {} tools", url, result.getToolCount());
            return result;
            
        } catch (Exception e) {
            logger.error("Error fetching content from {}: {}", url, e.getMessage());
            return CrawlResult.error(e.getMessage(), agentDescriptionUri, removeUrlParams(url));
        }
    }
    
    /**
     * Execute a tool call by name with given arguments.
     * 
     * This method finds the corresponding method info for the tool and executes
     * the JSON-RPC request to the appropriate server.
     * 
     * @param toolName The tool function name (from getOpenAiTools())
     * @param arguments Arguments to pass to the tool
     * @return Map containing execution result with keys: success, result/error, toolName, method, url
     */
    @SuppressWarnings("unchecked")
    public Map<String, Object> executeToolCall(String toolName, Map<String, Object> arguments) {
        logger.info("Executing tool call: {} with args size={}, keys={}", toolName, arguments.size(), arguments.keySet());
        
        CrawlResult.MethodInfo methodInfo = toolInterfaces.get(toolName);
        if (methodInfo == null) {
            Map<String, Object> errorResult = new LinkedHashMap<>();
            errorResult.put("success", false);
            errorResult.put("error", "No method found for tool: " + toolName);
            errorResult.put("toolName", toolName);
            return errorResult;
        }
        
        Map<String, Object> actualParams = arguments;
        if (arguments.size() == 1 && arguments.containsKey("params")) {
            Object paramsValue = arguments.get("params");
            logger.info("Found params key, value type: {}", paramsValue != null ? paramsValue.getClass().getName() : "null");
            if (paramsValue instanceof Map) {
                actualParams = (Map<String, Object>) paramsValue;
                logger.info("Unwrapped params from nested structure: {}", actualParams);
            }
        }
        logger.info("Final params for RPC call: {}", actualParams);
        
        try {
            Map<String, Object> result = executeJsonRpc(
                methodInfo.getRpcUrl(),
                methodInfo.getName(),
                actualParams
            );
            result.put("toolName", toolName);
            return result;
        } catch (Exception e) {
            Map<String, Object> errorResult = new LinkedHashMap<>();
            errorResult.put("success", false);
            errorResult.put("error", e.getMessage());
            errorResult.put("toolName", toolName);
            errorResult.put("url", methodInfo.getRpcUrl());
            errorResult.put("method", methodInfo.getName());
            return errorResult;
        }
    }
    
    /**
     * Execute JSON-RPC request directly.
     * 
     * @param endpoint JSON-RPC server endpoint URL
     * @param method Method name to call
     * @param params Method parameter map
     * @return Map containing execution result with keys: success, result/error, endpoint, method, requestId, response
     * @throws IOException If the request fails
     */
    public Map<String, Object> executeJsonRpc(String endpoint, String method, Map<String, Object> params) 
            throws IOException, InterruptedException {
        
        logger.info("Executing JSON-RPC: {} at {}", method, endpoint);
        
        String requestId = UUID.randomUUID().toString();
        
        // Process arguments to handle string JSON values
        Map<String, Object> processedParams = processJsonParams(params);
        
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("endpoint", endpoint);
        result.put("method", method);
        result.put("requestId", requestId);
        
        try {
            Object rpcResult = client.callJsonRpc(endpoint, method, processedParams);
            result.put("success", true);
            result.put("result", rpcResult);
            return result;
        } catch (ANPClient.RpcException e) {
            result.put("success", false);
            Map<String, Object> error = new LinkedHashMap<>();
            error.put("code", e.getCode());
            error.put("message", e.getMessage());
            error.put("data", e.getData());
            result.put("error", error);
            return result;
        } catch (Exception e) {
            result.put("success", false);
            result.put("error", e.getMessage());
            return result;
        }
    }
    
    /**
     * Get all discovered tools in OpenAI Tools format.
     * 
     * @return List of tools in OpenAI format
     */
    public List<Map<String, Object>> getOpenAiTools() {
        List<Map<String, Object>> tools = new ArrayList<>();
        
        for (CrawlResult.MethodInfo methodInfo : toolInterfaces.values()) {
            Map<String, Object> tool = new LinkedHashMap<>();
            tool.put("type", "function");
            
            Map<String, Object> function = new LinkedHashMap<>();
            function.put("name", methodInfo.getName());
            function.put("description", methodInfo.getDescription());
            function.put("parameters", methodInfo.getSchema());
            
            tool.put("function", function);
            tools.add(tool);
        }
        
        return tools;
    }
    
    /**
     * Get list of all available tool names.
     * 
     * @return List of tool names
     */
    public List<String> listAvailableTools() {
        return new ArrayList<>(toolInterfaces.keySet());
    }
    
    /**
     * Get interface info for a specific tool.
     * 
     * @param toolName The tool name
     * @return MethodInfo or null if not found
     */
    public CrawlResult.MethodInfo getToolInterfaceInfo(String toolName) {
        return toolInterfaces.get(toolName);
    }
    
    /**
     * Get list of all visited URLs.
     */
    public List<String> getVisitedUrls() {
        return new ArrayList<>(visitedUrls);
    }
    
    /**
     * Check if a URL has been visited.
     */
    public boolean isUrlVisited(String url) {
        return visitedUrls.contains(url);
    }
    
    /**
     * Get the number of cached entries.
     */
    public int getCacheSize() {
        return cache.size();
    }
    
    /**
     * Clear the session cache.
     */
    public void clearCache() {
        cache.clear();
        visitedUrls.clear();
        logger.info("Session cache cleared");
    }
    
    /**
     * Clear all stored tool interface mappings.
     */
    public void clearToolInterfaces() {
        toolInterfaces.clear();
        logger.info("Cleared all tool interface mappings");
    }
    
    /**
     * Get the ANP client instance.
     */
    public ANPClient getClient() {
        return client;
    }
    
    // ========================
    // Private helper methods
    // ========================
    
    /**
     * Parse interfaces from ad.json response.
     */
    @SuppressWarnings("unchecked")
    private void parseInterfaces(Map<String, Object> adJson, CrawlResult.Builder resultBuilder) {
        List<Map<String, Object>> interfaces = (List<Map<String, Object>>) adJson.get("interfaces");
        
        if (interfaces == null || interfaces.isEmpty()) {
            logger.debug("No interfaces found in ad.json");
            return;
        }
        
        for (Map<String, Object> iface : interfaces) {
            String type = (String) iface.get("type");
            String protocol = (String) iface.get("protocol");
            String interfaceUrl = (String) iface.get("url");
            
            // Handle case-insensitive type and various protocol formats
            boolean isStructuredInterface = type != null && type.equalsIgnoreCase("StructuredInterface");
            boolean isOpenRpcProtocol = protocol != null && 
                (protocol.equalsIgnoreCase("openrpc") || 
                 protocol.equalsIgnoreCase("JSON-RPC 2.0") ||
                 protocol.toLowerCase().contains("json-rpc"));
            
            if (isStructuredInterface && isOpenRpcProtocol && interfaceUrl != null) {
                try {
                    // Fetch OpenRPC document
                    Map<String, Object> openrpc = client.fetch(interfaceUrl);
                    parseOpenRpcMethods(openrpc, resultBuilder);
                } catch (Exception e) {
                    logger.warn("Failed to fetch interface from {}: {}", interfaceUrl, e.getMessage());
                }
            }
        }
    }
    
    /**
     * Parse methods from OpenRPC document.
     */
    @SuppressWarnings("unchecked")
    private void parseOpenRpcMethods(Map<String, Object> openrpc, CrawlResult.Builder resultBuilder) {
        List<Map<String, Object>> methods = (List<Map<String, Object>>) openrpc.get("methods");
        if (methods == null) {
            return;
        }
        
        // Get default server URL
        String defaultRpcUrl = null;
        List<Map<String, Object>> servers = (List<Map<String, Object>>) openrpc.get("servers");
        if (servers != null && !servers.isEmpty()) {
            defaultRpcUrl = (String) servers.get(0).get("url");
        }
        
        for (Map<String, Object> method : methods) {
            String name = (String) method.get("name");
            String description = (String) method.get("description");
            
            // Get RPC URL from method servers or default
            String rpcUrl = defaultRpcUrl;
            List<Map<String, Object>> methodServers = (List<Map<String, Object>>) method.get("servers");
            if (methodServers != null && !methodServers.isEmpty()) {
                rpcUrl = (String) methodServers.get(0).get("url");
            }
            
            if (rpcUrl == null) {
                logger.warn("No RPC URL for method: {}", name);
                continue;
            }
            
            // Build parameters schema
            Map<String, Object> schema = buildParametersSchema(method);
            
            // Create method info
            CrawlResult.MethodInfo methodInfo = new CrawlResult.MethodInfo(
                name,
                description != null ? description : "",
                rpcUrl,
                schema
            );
            
            // Store in tool interfaces map
            toolInterfaces.put(name, methodInfo);
            resultBuilder.addMethod(methodInfo);
            
            // Build OpenAI tool format
            Map<String, Object> tool = new LinkedHashMap<>();
            tool.put("type", "function");
            
            Map<String, Object> function = new LinkedHashMap<>();
            function.put("name", name);
            function.put("description", description != null ? description : "");
            function.put("parameters", schema);
            
            tool.put("function", function);
            resultBuilder.addTool(tool);
            
            logger.debug("Parsed method: {} with RPC URL: {}", name, rpcUrl);
        }
    }
    
    @SuppressWarnings("unchecked")
    private Map<String, Object> buildParametersSchema(Map<String, Object> method) {
        Object paramsObj = method.get("params");
        
        if (paramsObj == null) {
            Map<String, Object> emptySchema = new LinkedHashMap<>();
            emptySchema.put("type", "object");
            emptySchema.put("properties", new LinkedHashMap<>());
            return emptySchema;
        }
        
        if (paramsObj instanceof Map) {
            Map<String, Object> paramsMap = (Map<String, Object>) paramsObj;
            if ("object".equals(paramsMap.get("type")) && paramsMap.containsKey("properties")) {
                return paramsMap;
            }
        }
        
        Map<String, Object> schema = new LinkedHashMap<>();
        schema.put("type", "object");
        
        Map<String, Object> properties = new LinkedHashMap<>();
        List<String> required = new ArrayList<>();
        
        if (paramsObj instanceof List) {
            List<Map<String, Object>> params = (List<Map<String, Object>>) paramsObj;
            for (Map<String, Object> param : params) {
                String paramName = (String) param.get("name");
                Map<String, Object> paramSchema = (Map<String, Object>) param.get("schema");
                Boolean isRequired = (Boolean) param.get("required");
                
                if (paramSchema != null) {
                    properties.put(paramName, paramSchema);
                } else {
                    properties.put(paramName, Map.of("type", "object"));
                }
                
                if (isRequired != null && isRequired) {
                    required.add(paramName);
                }
            }
        }
        
        schema.put("properties", properties);
        if (!required.isEmpty()) {
            schema.put("required", required);
        }
        
        return schema;
    }
    
    /**
     * Process parameters to handle string JSON values.
     */
    private Map<String, Object> processJsonParams(Map<String, Object> params) {
        if (params == null) {
            return new HashMap<>();
        }
        
        Map<String, Object> processed = new LinkedHashMap<>();
        
        for (Map.Entry<String, Object> entry : params.entrySet()) {
            String key = entry.getKey();
            Object value = entry.getValue();
            
            if (value instanceof String) {
                String strValue = (String) value;
                // Try to parse as JSON if it looks like JSON
                if ((strValue.startsWith("{") && strValue.endsWith("}")) ||
                    (strValue.startsWith("[") && strValue.endsWith("]"))) {
                    try {
                        Object parsed = objectMapper.readValue(strValue, Object.class);
                        processed.put(key, parsed);
                        logger.debug("Parsed JSON parameter {}: {} -> {}", key, strValue, parsed);
                    } catch (JsonProcessingException e) {
                        processed.put(key, value);
                        logger.debug("Failed to parse JSON parameter {}: {}", key, strValue);
                    }
                } else {
                    processed.put(key, value);
                }
            } else {
                processed.put(key, value);
            }
        }
        
        return processed;
    }
    
    /**
     * Remove query parameters from URL.
     */
    private String removeUrlParams(String url) {
        try {
            URI uri = URI.create(url);
            return new URI(
                uri.getScheme(),
                uri.getAuthority(),
                uri.getPath(),
                null,  // query
                null   // fragment
            ).toString();
        } catch (Exception e) {
            logger.warn("Failed to parse URL {}: {}", url, e.getMessage());
            return url;
        }
    }
}
