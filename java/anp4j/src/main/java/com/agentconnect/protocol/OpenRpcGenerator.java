/**
 * @program: anp4java
 * @author: Ruitao.Zhai
 * @date: 2025-01-29
 */
package com.agentconnect.protocol;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.util.*;

/**
 * OpenRPC 1.3.2 interface document generator.
 * 
 * Generates interface.json documents following the OpenRPC specification.
 */
public final class OpenRpcGenerator {
    
    private static final String OPENRPC_VERSION = "1.3.2";
    private static final ObjectMapper objectMapper = new ObjectMapper();
    
    private OpenRpcGenerator() {}
    
    /**
     * Generate OpenRPC document for all content mode methods.
     * 
     * @param config Agent configuration
     * @param methods RPC method list
     * @param rpcUrl JSON-RPC endpoint URL
     * @return OpenRPC document as Map
     */
    public static Map<String, Object> generate(
            AgentConfig config,
            List<RPCMethodInfo> methods,
            String rpcUrl) {
        
        Map<String, Object> doc = new LinkedHashMap<>();
        
        // OpenRPC version
        doc.put("openrpc", OPENRPC_VERSION);
        
        // Info section
        Map<String, Object> info = new LinkedHashMap<>();
        info.put("title", config.getName() + " API");
        info.put("version", "1.0.0");
        info.put("description", config.getDescription());
        doc.put("info", info);
        
        // Methods
        List<Map<String, Object>> methodList = new ArrayList<>();
        for (RPCMethodInfo method : methods) {
            if (method.getMode() == RPCMethodInfo.Mode.CONTENT) {
                methodList.add(generateMethod(method, rpcUrl));
            }
        }
        doc.put("methods", methodList);
        
        // Servers
        List<Map<String, Object>> servers = new ArrayList<>();
        Map<String, Object> server = new LinkedHashMap<>();
        server.put("name", config.getName());
        server.put("url", rpcUrl);
        servers.add(server);
        doc.put("servers", servers);
        
        return doc;
    }
    
    /**
     * Generate OpenRPC document for a single method (link mode).
     * 
     * @param config Agent configuration
     * @param method RPC method
     * @param rpcUrl JSON-RPC endpoint URL
     * @return OpenRPC document as Map
     */
    public static Map<String, Object> generateSingle(
            AgentConfig config,
            RPCMethodInfo method,
            String rpcUrl) {
        
        Map<String, Object> doc = new LinkedHashMap<>();
        
        // OpenRPC version
        doc.put("openrpc", OPENRPC_VERSION);
        
        // Info section
        Map<String, Object> info = new LinkedHashMap<>();
        info.put("title", method.getName());
        info.put("version", "1.0.0");
        info.put("description", method.getDescription());
        doc.put("info", info);
        
        // Single method
        List<Map<String, Object>> methods = new ArrayList<>();
        methods.add(generateMethod(method, rpcUrl));
        doc.put("methods", methods);
        
        // Servers
        List<Map<String, Object>> servers = new ArrayList<>();
        Map<String, Object> server = new LinkedHashMap<>();
        server.put("name", config.getName());
        server.put("url", rpcUrl);
        servers.add(server);
        doc.put("servers", servers);
        
        return doc;
    }
    
    /**
     * Generate method object.
     */
    private static Map<String, Object> generateMethod(RPCMethodInfo method, String rpcUrl) {
        Map<String, Object> m = new LinkedHashMap<>();
        
        m.put("name", method.getName());
        m.put("description", method.getDescription());
        
        // Parameters
        List<Map<String, Object>> params = generateParams(method.getParamsSchema());
        m.put("params", params);
        
        // Result
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("name", "result");
        result.put("schema", method.getResultSchema() != null 
            ? method.getResultSchema() 
            : Map.of("type", "object"));
        m.put("result", result);
        
        // Protocol extension (for AP2 etc.)
        if (method.getProtocol() != null) {
            m.put("x-protocol", method.getProtocol());
        }
        
        // Servers for this method
        List<Map<String, Object>> servers = new ArrayList<>();
        Map<String, Object> server = new LinkedHashMap<>();
        server.put("url", rpcUrl);
        servers.add(server);
        m.put("servers", servers);
        
        return m;
    }
    
    /**
     * Generate params array from schema.
     */
    private static List<Map<String, Object>> generateParams(Map<String, Object> paramsSchema) {
        List<Map<String, Object>> params = new ArrayList<>();
        
        if (paramsSchema == null) {
            return params;
        }
        
        // Extract from JSON Schema object format
        @SuppressWarnings("unchecked")
        Map<String, Object> properties = (Map<String, Object>) paramsSchema.get("properties");
        @SuppressWarnings("unchecked")
        List<String> required = (List<String>) paramsSchema.get("required");
        Set<String> requiredSet = required != null ? new HashSet<>(required) : Collections.emptySet();
        
        if (properties != null) {
            for (Map.Entry<String, Object> entry : properties.entrySet()) {
                String paramName = entry.getKey();
                @SuppressWarnings("unchecked")
                Map<String, Object> paramSchema = (Map<String, Object>) entry.getValue();
                
                Map<String, Object> param = new LinkedHashMap<>();
                param.put("name", paramName);
                param.put("schema", paramSchema);
                param.put("required", requiredSet.contains(paramName));
                
                params.add(param);
            }
        }
        
        return params;
    }
    
    /**
     * Convert to JSON string.
     */
    public static String toJson(Map<String, Object> doc) throws JsonProcessingException {
        return objectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(doc);
    }
    
    /**
     * Convert OpenRPC methods to OpenAI Tools format.
     * 
     * @param methods List of RPC method info
     * @return List of OpenAI tool definitions
     */
    public static List<Map<String, Object>> toOpenAITools(List<RPCMethodInfo> methods) {
        List<Map<String, Object>> tools = new ArrayList<>();
        
        for (RPCMethodInfo method : methods) {
            Map<String, Object> tool = new LinkedHashMap<>();
            tool.put("type", "function");
            
            Map<String, Object> function = new LinkedHashMap<>();
            function.put("name", method.getName());
            function.put("description", method.getDescription());
            
            // Parameters schema
            Map<String, Object> parameters = new LinkedHashMap<>();
            if (method.getParamsSchema() != null) {
                parameters.putAll(method.getParamsSchema());
            } else {
                parameters.put("type", "object");
                parameters.put("properties", new LinkedHashMap<>());
            }
            function.put("parameters", parameters);
            
            tool.put("function", function);
            tools.add(tool);
        }
        
        return tools;
    }
}
