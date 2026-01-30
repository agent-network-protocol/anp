/**
 * @program: anp4java
 * @author: Ruitao.Zhai
 * @date: 2025-01-29
 */
package com.agentconnect.client;

import com.agentconnect.authentication.DIDWbaAuthHeader;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.stream.Collectors;

/**
 * Handle to a discovered remote ANP agent.
 * 
 * RemoteAgent downloads all methods from a remote agent and transforms them into
 * callable methods. It creates a proxy object that makes calling remote agents
 * feel like calling local methods.
 * 
 * Example:
 *     DIDWbaAuthHeader auth = new DIDWbaAuthHeader(
 *         "/path/to/did-doc.json",
 *         "/path/to/private-key.pem"
 *     );
 *     
 *     // Discover agent
 *     RemoteAgent agent = RemoteAgent.discover("https://hotel.example.com/ad.json", auth);
 *     
 *     // Inspect available methods
 *     System.out.println("Agent: " + agent.getName());
 *     System.out.println("Methods: " + agent.getMethodNames());
 *     
 *     // Call methods
 *     Object result = agent.call("search", Map.of("query", "Tokyo"));
 *     
 *     // Get OpenAI Tools format
 *     List<Map<String, Object>> tools = agent.getTools();
 */
public class RemoteAgent {
    
    private static final Logger logger = LoggerFactory.getLogger(RemoteAgent.class);
    
    private final String url;
    private final String name;
    private final String description;
    private final List<Method> methods;
    private final ANPClient client;
    
    private RemoteAgent(String url, String name, String description, List<Method> methods, ANPClient client) {
        this.url = url;
        this.name = name;
        this.description = description;
        this.methods = Collections.unmodifiableList(methods);
        this.client = client;
    }
    
    /**
     * Discover agent from AD URL.
     * 
     * @param adUrl The URL to the agent's ad.json
     * @param auth DID-WBA authentication header
     * @return RemoteAgent instance
     * @throws IOException If discovery fails
     */
    public static RemoteAgent discover(String adUrl, DIDWbaAuthHeader auth) throws IOException, InterruptedException {
        logger.info("Discovering agent from: {}", adUrl);
        
        ANPClient client = new ANPClient(auth);
        
        // Fetch ad.json
        Map<String, Object> ad = client.fetch(adUrl);
        
        String name = requireString(ad, "name", "ad.name");
        String description = getString(ad, "description", name);
        
        // Parse interfaces
        List<Method> methods = new ArrayList<>();
        
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> interfaces = (List<Map<String, Object>>) ad.get("interfaces");
        
        if (interfaces == null || interfaces.isEmpty()) {
            throw new IllegalArgumentException("No interfaces found at " + adUrl);
        }
        
        for (Map<String, Object> iface : interfaces) {
            String type = (String) iface.get("type");
            String protocol = (String) iface.get("protocol");
            String interfaceUrl = (String) iface.get("url");
            
            boolean isStructuredInterface = type != null && 
                type.toLowerCase().contains("structuredinterface");
            boolean isJsonRpcProtocol = protocol != null && 
                (protocol.equalsIgnoreCase("openrpc") ||
                 protocol.equalsIgnoreCase("JSON-RPC 2.0") ||
                 protocol.toLowerCase().contains("json-rpc"));
            
            if (isStructuredInterface && isJsonRpcProtocol && interfaceUrl != null) {
                // Fetch OpenRPC document
                try {
                    Map<String, Object> openrpc = client.fetch(interfaceUrl);
                    methods.addAll(parseOpenRpcMethods(openrpc));
                } catch (Exception e) {
                    logger.warn("Failed to fetch interface from {}: {}", interfaceUrl, e.getMessage());
                }
            }
        }
        
        if (methods.isEmpty()) {
            throw new IllegalArgumentException("No callable methods found at " + adUrl);
        }
        
        logger.info("Discovered agent {} with {} methods", name, methods.size());
        return new RemoteAgent(adUrl, name, description, methods, client);
    }
    
    /**
     * Discover agent asynchronously.
     */
    public static CompletableFuture<RemoteAgent> discoverAsync(String adUrl, DIDWbaAuthHeader auth) {
        return CompletableFuture.supplyAsync(() -> {
            try {
                return discover(adUrl, auth);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        });
    }
    
    /**
     * Get agent URL.
     */
    public String getUrl() {
        return url;
    }
    
    /**
     * Get agent name.
     */
    public String getName() {
        return name;
    }
    
    /**
     * Get agent description.
     */
    public String getDescription() {
        return description;
    }
    
    /**
     * Get all methods.
     */
    public List<Method> getMethods() {
        return methods;
    }
    
    /**
     * Get method names.
     */
    public List<String> getMethodNames() {
        List<String> names = new ArrayList<>();
        for (Method m : methods) {
            names.add(m.getName());
        }
        return names;
    }
    
    /**
     * Get a method by name.
     * 
     * @throws IllegalArgumentException If method not found
     */
    public Method getMethod(String name) {
        for (Method m : methods) {
            if (m.getName().equals(name)) {
                return m;
            }
        }
        throw new IllegalArgumentException("Method not found: " + name);
    }
    
    /**
     * Call a method.
     * 
     * @param methodName The method name
     * @param params The method parameters
     * @return The result
     * @throws IOException If the call fails
     */
    public Object call(String methodName, Map<String, Object> params) throws IOException, InterruptedException {
        Method method = getMethod(methodName);
        return client.callJsonRpc(method.getRpcUrl(), methodName, params);
    }
    
    /**
     * Call a method asynchronously.
     */
    public CompletableFuture<Object> callAsync(String methodName, Map<String, Object> params) {
        return CompletableFuture.supplyAsync(() -> {
            try {
                return call(methodName, params);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        });
    }
    
    /**
     * Get OpenAI Tools format for all methods.
     */
    public List<Map<String, Object>> getTools() {
        List<Map<String, Object>> tools = new ArrayList<>();
        
        for (Method method : methods) {
            Map<String, Object> tool = new LinkedHashMap<>();
            tool.put("type", "function");
            
            Map<String, Object> function = new LinkedHashMap<>();
            function.put("name", method.getName());
            function.put("description", method.getDescription());
            
            // Build parameters schema
            Map<String, Object> parameters = new LinkedHashMap<>();
            parameters.put("type", "object");
            
            Map<String, Object> properties = new LinkedHashMap<>();
            List<String> required = new ArrayList<>();
            
            for (Method.Param param : method.getParams()) {
                properties.put(param.getName(), param.getSchema());
                if (param.isRequired()) {
                    required.add(param.getName());
                }
            }
            
            parameters.put("properties", properties);
            if (!required.isEmpty()) {
                parameters.put("required", required);
            }
            
            function.put("parameters", parameters);
            tool.put("function", function);
            tools.add(tool);
        }
        
        return tools;
    }
    
    @Override
    public String toString() {
        return "RemoteAgent{name='" + name + "', methods=" + getMethodNames() + "}";
    }
    
    // ========================
    // Helper methods
    // ========================
    
    private static String requireString(Map<String, Object> map, String key, String field) {
        Object value = map.get(key);
        if (!(value instanceof String) || ((String) value).trim().isEmpty()) {
            throw new IllegalArgumentException(field + " must be a non-empty string");
        }
        return ((String) value).trim();
    }
    
    private static String getString(Map<String, Object> map, String key, String defaultValue) {
        Object value = map.get(key);
        if (value instanceof String && !((String) value).trim().isEmpty()) {
            return ((String) value).trim();
        }
        return defaultValue;
    }
    
    @SuppressWarnings("unchecked")
    private static List<Method> parseOpenRpcMethods(Map<String, Object> openrpc) {
        List<Method> methods = new ArrayList<>();
        
        List<Map<String, Object>> methodList = (List<Map<String, Object>>) openrpc.get("methods");
        if (methodList == null) {
            return methods;
        }
        
        // Get default server URL
        String defaultRpcUrl = null;
        List<Map<String, Object>> servers = (List<Map<String, Object>>) openrpc.get("servers");
        if (servers != null && !servers.isEmpty()) {
            defaultRpcUrl = (String) servers.get(0).get("url");
        }
        
        for (Map<String, Object> m : methodList) {
            String name = (String) m.get("name");
            String description = (String) m.get("description");
            
            // Get RPC URL from method servers or default
            String rpcUrl = defaultRpcUrl;
            List<Map<String, Object>> methodServers = (List<Map<String, Object>>) m.get("servers");
            if (methodServers != null && !methodServers.isEmpty()) {
                rpcUrl = (String) methodServers.get(0).get("url");
            }
            
            if (rpcUrl == null) {
                logger.warn("No RPC URL for method: {}", name);
                continue;
            }
            
            // Parse params (supports both array and object schema formats)
            List<Method.Param> params = new ArrayList<>();
            Object paramsObj = m.get("params");
            
            if (paramsObj instanceof List) {
                List<Map<String, Object>> paramList = (List<Map<String, Object>>) paramsObj;
                for (Map<String, Object> p : paramList) {
                    String paramName = (String) p.get("name");
                    Map<String, Object> schema = (Map<String, Object>) p.get("schema");
                    Boolean required = (Boolean) p.get("required");
                    params.add(new Method.Param(paramName, schema, required != null && required));
                }
            } else if (paramsObj instanceof Map) {
                Map<String, Object> paramsSchema = (Map<String, Object>) paramsObj;
                Map<String, Object> properties = (Map<String, Object>) paramsSchema.get("properties");
                List<String> requiredList = (List<String>) paramsSchema.get("required");
                Set<String> requiredSet = requiredList != null ? new HashSet<>(requiredList) : Collections.emptySet();
                
                if (properties != null) {
                    for (Map.Entry<String, Object> entry : properties.entrySet()) {
                        String paramName = entry.getKey();
                        Map<String, Object> schema = (Map<String, Object>) entry.getValue();
                        boolean isRequired = requiredSet.contains(paramName);
                        params.add(new Method.Param(paramName, schema, isRequired));
                    }
                }
            }
            
            methods.add(new Method(name, description != null ? description : "", params, rpcUrl));
        }
        
        return methods;
    }
    
    /**
     * Method definition.
     */
    public static class Method {
        private final String name;
        private final String description;
        private final List<Param> params;
        private final String rpcUrl;
        
        public Method(String name, String description, List<Param> params, String rpcUrl) {
            this.name = name;
            this.description = description;
            this.params = Collections.unmodifiableList(params);
            this.rpcUrl = rpcUrl;
        }
        
        public String getName() {
            return name;
        }
        
        public String getDescription() {
            return description;
        }
        
        public List<Param> getParams() {
            return params;
        }
        
        public String getRpcUrl() {
            return rpcUrl;
        }
        
        @Override
        public String toString() {
            return "Method{name='" + name + "'}";
        }
        
        /**
         * Parameter definition.
         */
        public static class Param {
            private final String name;
            private final Map<String, Object> schema;
            private final boolean required;
            
            public Param(String name, Map<String, Object> schema, boolean required) {
                this.name = name;
                this.schema = schema != null ? schema : Map.of("type", "object");
                this.required = required;
            }
            
            public String getName() {
                return name;
            }
            
            public Map<String, Object> getSchema() {
                return schema;
            }
            
            public boolean isRequired() {
                return required;
            }
        }
    }
}
