/**
 * @program: anp4java
 * @author: Ruitao.Zhai
 * @date: 2025-01-29
 */
package com.agentconnect.server;

import com.agentconnect.protocol.*;
import com.agentconnect.server.annotation.AnpAgent;
import com.agentconnect.server.annotation.Interface;
import com.agentconnect.server.annotation.Param;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.lang.reflect.Method;
import java.lang.reflect.Parameter;
import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;

/**
 * ANP Agent Handler - Processes RPC methods and generates protocol documents.
 * 
 * This class scans an agent instance for @Interface annotated methods and
 * provides handlers for ad.json, interface.json, and JSON-RPC endpoints.
 * 
 * Example:
 *     {@literal @}AnpAgent(name = "Hotel", did = "did:wba:example.com:hotel", prefix = "/hotel")
 *     public class HotelAgent {
 *         {@literal @}Interface
 *         public Map<String, Object> search(String query) {
 *             return Map.of("results", List.of());
 *         }
 *     }
 *     
 *     HotelAgent agent = new HotelAgent();
 *     AgentHandler handler = new AgentHandler(agent);
 *     
 *     // Get protocol documents
 *     Map<String, Object> ad = handler.getAgentDescription("http://localhost:8080");
 *     Map<String, Object> openrpc = handler.getOpenRpcDocument("http://localhost:8080/hotel/rpc");
 *     
 *     // Handle RPC call
 *     Object result = handler.handleRpc("search", Map.of("query", "Tokyo"), context);
 */
public class AgentHandler {
    
    private static final Logger logger = LoggerFactory.getLogger(AgentHandler.class);
    private static final ObjectMapper objectMapper = new ObjectMapper();
    
    private final Object agentInstance;
    private final AgentConfig config;
    private final List<RPCMethodInfo> methods;
    private final Map<String, MethodHandler> methodHandlers;
    private final SessionManager sessionManager;
    
    /**
     * Create an agent handler from an annotated agent instance.
     * 
     * @param agentInstance The agent instance with @AnpAgent annotation
     */
    public AgentHandler(Object agentInstance) {
        this(agentInstance, (AgentConfig) null);
    }
    
    /**
     * Create an agent handler with external config.
     * 
     * @param agentInstance The agent instance
     * @param config External configuration (overrides annotation)
     */
    public AgentHandler(Object agentInstance, AgentConfig config) {
        this(agentInstance, config, new SessionManager());
    }
    
    /**
     * Create an agent handler with a custom session manager.
     */
    public AgentHandler(Object agentInstance, SessionManager sessionManager) {
        this(agentInstance, null, sessionManager);
    }
    
    /**
     * Full constructor with all options.
     */
    public AgentHandler(Object agentInstance, AgentConfig externalConfig, SessionManager sessionManager) {
        this.agentInstance = agentInstance;
        this.sessionManager = sessionManager;
        
        Class<?> clazz = agentInstance.getClass();
        
        if (externalConfig != null) {
            this.config = externalConfig;
        } else {
            AnpAgent annotation = clazz.getAnnotation(AnpAgent.class);
            if (annotation == null) {
                throw new IllegalArgumentException("Agent class must have @AnpAgent annotation or provide external config");
            }
            
            this.config = AgentConfig.builder()
                .name(annotation.name())
                .did(annotation.did())
                .description(annotation.description().isEmpty() ? annotation.name() : annotation.description())
                .prefix(annotation.prefix())
                .tags(Arrays.asList(annotation.tags()))
                .build();
        }
        
        // Extract methods
        this.methods = extractMethods(clazz);
        this.methodHandlers = buildMethodHandlers(clazz);
        
        logger.info("AgentHandler initialized for {} with {} methods", 
            config.getName(), methods.size());
    }
    
    /**
     * Get the agent configuration.
     */
    public AgentConfig getConfig() {
        return config;
    }
    
    /**
     * Get all RPC methods.
     */
    public List<RPCMethodInfo> getMethods() {
        return Collections.unmodifiableList(methods);
    }
    
    /**
     * Generate Agent Description (ad.json).
     * 
     * @param baseUrl The base URL for generating interface URLs
     * @return ad.json as Map
     */
    public Map<String, Object> getAgentDescription(String baseUrl) {
        return AgentDescription.generate(config, methods, null, baseUrl);
    }
    
    /**
     * Generate OpenRPC document (interface.json).
     * 
     * @param rpcUrl The JSON-RPC endpoint URL
     * @return OpenRPC document as Map
     */
    public Map<String, Object> getOpenRpcDocument(String rpcUrl) {
        return OpenRpcGenerator.generate(config, methods, rpcUrl);
    }
    
    /**
     * Generate OpenRPC document for a single method (link mode).
     * 
     * @param methodName The method name
     * @param rpcUrl The JSON-RPC endpoint URL
     * @return OpenRPC document as Map
     */
    public Map<String, Object> getSingleMethodDocument(String methodName, String rpcUrl) {
        RPCMethodInfo method = findMethod(methodName);
        if (method == null) {
            throw new IllegalArgumentException("Method not found: " + methodName);
        }
        return OpenRpcGenerator.generateSingle(config, method, rpcUrl);
    }
    
    /**
     * Get OpenAI Tools format for all methods.
     */
    public List<Map<String, Object>> getOpenAITools() {
        return OpenRpcGenerator.toOpenAITools(methods);
    }
    
    /**
     * Generate ad.json as JSON string (uses config.baseUrl).
     */
    public String generateAgentDescription() {
        String baseUrl = config.getBaseUrl();
        if (baseUrl == null || baseUrl.isEmpty()) {
            baseUrl = "http://localhost:8080";
        }
        return generateAgentDescription(baseUrl);
    }
    
    /**
     * Generate ad.json as JSON string with specified baseUrl.
     */
    public String generateAgentDescription(String baseUrl) {
        try {
            return objectMapper.writeValueAsString(getAgentDescription(baseUrl));
        } catch (Exception e) {
            throw new RuntimeException("Failed to serialize agent description", e);
        }
    }
    
    /**
     * Generate OpenRPC as JSON string (uses config.baseUrl + prefix).
     */
    public String generateOpenRpc() {
        String baseUrl = config.getBaseUrl();
        if (baseUrl == null || baseUrl.isEmpty()) {
            baseUrl = "http://localhost:8080";
        }
        String rpcUrl = baseUrl + config.getPrefix() + "/rpc";
        return generateOpenRpc(rpcUrl);
    }
    
    /**
     * Generate OpenRPC as JSON string with specified rpcUrl.
     */
    public String generateOpenRpc(String rpcUrl) {
        try {
            return objectMapper.writeValueAsString(getOpenRpcDocument(rpcUrl));
        } catch (Exception e) {
            throw new RuntimeException("Failed to serialize OpenRPC document", e);
        }
    }
    
    /**
     * Handle raw JSON-RPC request string with callerDid.
     */
    public String handleRequest(String jsonRequest, String callerDid) {
        Context context = createContext(callerDid, null, null);
        return handleRequest(jsonRequest, context);
    }
    
    /**
     * Handle raw JSON-RPC request string with full Context.
     */
    public String handleRequest(String jsonRequest, Context context) {
        try {
            JsonRpc.Request request = objectMapper.readValue(jsonRequest, JsonRpc.Request.class);
            JsonRpc.Response response = handleRpc(request, context);
            return objectMapper.writeValueAsString(response);
        } catch (Exception e) {
            logger.error("Failed to handle request: {}", e.getMessage());
            JsonRpc.Response errorResponse = JsonRpc.Response.error(
                JsonRpc.Error.parseError(e.getMessage()), null);
            try {
                return objectMapper.writeValueAsString(errorResponse);
            } catch (Exception ex) {
                return "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32700,\"message\":\"Parse error\"},\"id\":null}";
            }
        }
    }
    
    /**
     * Handle a JSON-RPC request.
     * 
     * @param request The JSON-RPC request
     * @param context The request context (can be null)
     * @return JSON-RPC response
     */
    public JsonRpc.Response handleRpc(JsonRpc.Request request, Context context) {
        if (!request.isValid()) {
            return JsonRpc.Response.error(
                JsonRpc.Error.invalidRequest("Invalid JSON-RPC request"),
                request.getId()
            );
        }
        
        String methodName = request.getMethod();
        Map<String, Object> params = request.getParams();
        
        try {
            Object result = handleRpc(methodName, params != null ? params : new HashMap<>(), context);
            return JsonRpc.Response.success(result, request.getId());
        } catch (JsonRpc.RpcException e) {
            return JsonRpc.Response.error(e.getError(), request.getId());
        } catch (Exception e) {
            logger.error("Error handling RPC method {}: {}", methodName, e.getMessage(), e);
            return JsonRpc.Response.error(
                JsonRpc.Error.internalError(e.getMessage()),
                request.getId()
            );
        }
    }
    
    /**
     * Handle a method call directly.
     * 
     * @param methodName The method name
     * @param params The method parameters
     * @param context The request context (can be null)
     * @return The method result
     */
    public Object handleRpc(String methodName, Map<String, Object> params, Context context) {
        MethodHandler handler = methodHandlers.get(methodName);
        if (handler == null) {
            throw new JsonRpc.RpcException(
                JsonRpc.METHOD_NOT_FOUND,
                "Method not found: " + methodName
            );
        }
        
        try {
            return handler.invoke(params, context);
        } catch (JsonRpc.RpcException e) {
            throw e;
        } catch (Exception e) {
            logger.error("Error invoking method {}: {}", methodName, e.getMessage(), e);
            throw new JsonRpc.RpcException(JsonRpc.INTERNAL_ERROR, e.getMessage());
        }
    }
    
    /**
     * Create a context for a request.
     * 
     * @param did The caller's DID
     * @param authResult Authentication result
     * @param headers Request headers
     * @return The context
     */
    public Context createContext(String did, Map<String, Object> authResult, Map<String, String> headers) {
        Context.Session session = sessionManager.getSession(did);
        return new Context(did, session, authResult, headers);
    }
    
    /**
     * Find a method by name.
     */
    private RPCMethodInfo findMethod(String name) {
        for (RPCMethodInfo method : methods) {
            if (method.getName().equals(name)) {
                return method;
            }
        }
        return null;
    }
    
    /**
     * Extract RPC methods from class.
     */
    private List<RPCMethodInfo> extractMethods(Class<?> clazz) {
        List<RPCMethodInfo> result = new ArrayList<>();
        
        for (Method method : clazz.getMethods()) {
            Interface annotation = method.getAnnotation(Interface.class);
            if (annotation == null) {
                continue;
            }
            
            String name = annotation.name().isEmpty() ? method.getName() : annotation.name();
            String description = annotation.description().isEmpty() 
                ? "Method " + name 
                : annotation.description();
            String protocol = annotation.protocol().isEmpty() ? null : annotation.protocol();
            
            // Check if method has Context parameter
            boolean hasContext = false;
            for (Parameter param : method.getParameters()) {
                if (Context.class.isAssignableFrom(param.getType())) {
                    hasContext = true;
                    break;
                }
            }
            
            // Generate schema from method signature
            Map<String, Object> paramsSchema = generateParamsSchema(method);
            Map<String, Object> resultSchema = generateResultSchema(method);
            
            result.add(RPCMethodInfo.builder()
                .name(name)
                .description(description)
                .paramsSchema(paramsSchema)
                .resultSchema(resultSchema)
                .handler(method)
                .protocol(protocol)
                .mode(annotation.mode())
                .hasContext(hasContext)
                .build());
        }
        
        return result;
    }
    
    /**
     * Build method handlers.
     */
    private Map<String, MethodHandler> buildMethodHandlers(Class<?> clazz) {
        Map<String, MethodHandler> handlers = new HashMap<>();
        
        for (Method method : clazz.getMethods()) {
            Interface annotation = method.getAnnotation(Interface.class);
            if (annotation == null) {
                continue;
            }
            
            String name = annotation.name().isEmpty() ? method.getName() : annotation.name();
            handlers.put(name, new MethodHandler(method, agentInstance));
        }
        
        return handlers;
    }
    
    /**
     * Generate parameters schema from method signature.
     */
    private Map<String, Object> generateParamsSchema(Method method) {
        Map<String, Object> schema = new LinkedHashMap<>();
        schema.put("type", "object");
        
        Map<String, Object> properties = new LinkedHashMap<>();
        List<String> required = new ArrayList<>();
        
        for (Parameter param : method.getParameters()) {
            // Skip Context parameter
            if (Context.class.isAssignableFrom(param.getType())) {
                continue;
            }
            
            String paramName = param.getName();
            properties.put(paramName, typeToSchema(param.getType()));
            required.add(paramName);
        }
        
        schema.put("properties", properties);
        if (!required.isEmpty()) {
            schema.put("required", required);
        }
        
        return schema;
    }
    
    /**
     * Generate result schema from method return type.
     */
    private Map<String, Object> generateResultSchema(Method method) {
        return typeToSchema(method.getReturnType());
    }
    
    /**
     * Convert Java type to JSON Schema.
     */
    private Map<String, Object> typeToSchema(Class<?> type) {
        Map<String, Object> schema = new LinkedHashMap<>();
        
        if (type == String.class) {
            schema.put("type", "string");
        } else if (type == int.class || type == Integer.class) {
            schema.put("type", "integer");
        } else if (type == long.class || type == Long.class) {
            schema.put("type", "integer");
        } else if (type == double.class || type == Double.class || 
                   type == float.class || type == Float.class) {
            schema.put("type", "number");
        } else if (type == boolean.class || type == Boolean.class) {
            schema.put("type", "boolean");
        } else if (type.isArray() || List.class.isAssignableFrom(type)) {
            schema.put("type", "array");
            schema.put("items", Map.of("type", "object"));
        } else {
            schema.put("type", "object");
        }
        
        return schema;
    }
    
    /**
     * Internal method handler.
     * 
     * Supports two method signature styles:
     * 
     * 1. Old style (Map params):
     *    public Map<String, Object> method(Map<String, Object> params, Context ctx)
     * 
     * 2. New style (direct params with @Param):
     *    public int add(@Param("a") int a, @Param("b") int b)
     *    public int add(@Param("a") int a, @Param("b") int b, Context ctx)
     */
    private static class MethodHandler {
        private final Method method;
        private final Object instance;
        private final List<ParamInfo> paramInfos;
        private final boolean isAsync;
        
        MethodHandler(Method method, Object instance) {
            this.method = method;
            this.instance = instance;
            this.paramInfos = extractParamInfos(method);
            Class<?> returnType = method.getReturnType();
            this.isAsync = CompletableFuture.class.isAssignableFrom(returnType) 
                        || CompletionStage.class.isAssignableFrom(returnType);
        }
        
        boolean isAsync() {
            return isAsync;
        }
        
        Object invoke(Map<String, Object> params, Context context) throws Exception {
            Object[] args = new Object[paramInfos.size()];
            
            // Check if this is a single-Map-param method (pass entire params map)
            boolean singleMapParam = isSingleMapParamMethod();
            
            for (int i = 0; i < paramInfos.size(); i++) {
                ParamInfo info = paramInfos.get(i);
                if (info.isContext) {
                    args[i] = context;
                } else if (singleMapParam && Map.class.isAssignableFrom(info.type)) {
                    args[i] = params != null ? params : new HashMap<>();
                } else {
                    Object value = params != null ? params.get(info.name) : null;
                    
                    if (value == null && info.defaultValue != null) {
                        value = parseDefaultValue(info.defaultValue, info.type);
                    }
                    
                    if (value == null && info.required && !info.type.isPrimitive()) {
                        throw new JsonRpc.RpcException(
                            JsonRpc.INVALID_PARAMS,
                            "Missing required parameter: " + info.name
                        );
                    }
                    
                    args[i] = convertValue(value, info.type);
                }
            }
            
            Object result = method.invoke(instance, args);
            
            if (isAsync && result != null) {
                if (result instanceof CompletableFuture) {
                    result = ((CompletableFuture<?>) result).get();
                } else if (result instanceof CompletionStage) {
                    result = ((CompletionStage<?>) result).toCompletableFuture().get();
                }
            }
            
            return result;
        }
        
        CompletableFuture<Object> invokeAsync(Map<String, Object> params, Context context) {
            return CompletableFuture.supplyAsync(() -> {
                try {
                    return invoke(params, context);
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            });
        }
        
        private boolean isSingleMapParamMethod() {
            int nonContextParams = 0;
            boolean hasMapParam = false;
            for (ParamInfo info : paramInfos) {
                if (!info.isContext) {
                    nonContextParams++;
                    if (Map.class.isAssignableFrom(info.type)) {
                        hasMapParam = true;
                    }
                }
            }
            return nonContextParams == 1 && hasMapParam;
        }
        
        private static List<ParamInfo> extractParamInfos(Method method) {
            List<ParamInfo> infos = new ArrayList<>();
            for (Parameter param : method.getParameters()) {
                boolean isContext = Context.class.isAssignableFrom(param.getType());
                String paramName = param.getName();
                String description = "";
                boolean required = true;
                String defaultValue = null;
                
                Param paramAnnotation = param.getAnnotation(Param.class);
                if (paramAnnotation != null) {
                    if (!paramAnnotation.value().isEmpty()) {
                        paramName = paramAnnotation.value();
                    }
                    description = paramAnnotation.description();
                    required = paramAnnotation.required();
                    if (!paramAnnotation.defaultValue().isEmpty()) {
                        defaultValue = paramAnnotation.defaultValue();
                    }
                }
                
                infos.add(new ParamInfo(paramName, param.getType(), isContext, description, required, defaultValue));
            }
            return infos;
        }
        
        private static Object parseDefaultValue(String defaultValue, Class<?> targetType) {
            if (defaultValue == null || defaultValue.isEmpty()) {
                return null;
            }
            
            try {
                if (targetType == String.class) {
                    if (defaultValue.startsWith("\"") && defaultValue.endsWith("\"")) {
                        return defaultValue.substring(1, defaultValue.length() - 1);
                    }
                    return defaultValue;
                } else if (targetType == int.class || targetType == Integer.class) {
                    return Integer.parseInt(defaultValue);
                } else if (targetType == long.class || targetType == Long.class) {
                    return Long.parseLong(defaultValue);
                } else if (targetType == double.class || targetType == Double.class) {
                    return Double.parseDouble(defaultValue);
                } else if (targetType == boolean.class || targetType == Boolean.class) {
                    return Boolean.parseBoolean(defaultValue);
                }
                return objectMapper.readValue(defaultValue, targetType);
            } catch (Exception e) {
                return null;
            }
        }
        
        private static Object convertValue(Object value, Class<?> targetType) {
            if (value == null) {
                if (targetType == int.class) return 0;
                if (targetType == long.class) return 0L;
                if (targetType == double.class) return 0.0;
                if (targetType == float.class) return 0.0f;
                if (targetType == boolean.class) return false;
                return null;
            }
            
            if (targetType.isInstance(value)) {
                return value;
            }
            
            // Basic type conversions
            if (targetType == String.class) {
                return String.valueOf(value);
            } else if (targetType == int.class || targetType == Integer.class) {
                if (value instanceof Number) {
                    return ((Number) value).intValue();
                }
                return Integer.parseInt(String.valueOf(value));
            } else if (targetType == long.class || targetType == Long.class) {
                if (value instanceof Number) {
                    return ((Number) value).longValue();
                }
                return Long.parseLong(String.valueOf(value));
            } else if (targetType == double.class || targetType == Double.class) {
                if (value instanceof Number) {
                    return ((Number) value).doubleValue();
                }
                return Double.parseDouble(String.valueOf(value));
            } else if (targetType == float.class || targetType == Float.class) {
                if (value instanceof Number) {
                    return ((Number) value).floatValue();
                }
                return Float.parseFloat(String.valueOf(value));
            } else if (targetType == boolean.class || targetType == Boolean.class) {
                if (value instanceof Boolean) {
                    return value;
                }
                return Boolean.parseBoolean(String.valueOf(value));
            }
            
            try {
                return objectMapper.convertValue(value, targetType);
            } catch (Exception e) {
                return value;
            }
        }
        
        private static class ParamInfo {
            final String name;
            final Class<?> type;
            final boolean isContext;
            final String description;
            final boolean required;
            final String defaultValue;
            
            ParamInfo(String name, Class<?> type, boolean isContext, 
                      String description, boolean required, String defaultValue) {
                this.name = name;
                this.type = type;
                this.isContext = isContext;
                this.description = description;
                this.required = required;
                this.defaultValue = defaultValue;
            }
        }
    }
    
    /**
     * Handle RPC call asynchronously.
     * 
     * @param methodName The method name
     * @param params The method parameters
     * @param context The request context
     * @return CompletableFuture with the result
     */
    public CompletableFuture<Object> handleRpcAsync(String methodName, Map<String, Object> params, Context context) {
        MethodHandler handler = methodHandlers.get(methodName);
        if (handler == null) {
            return CompletableFuture.failedFuture(new JsonRpc.RpcException(
                JsonRpc.METHOD_NOT_FOUND,
                "Method not found: " + methodName
            ));
        }
        
        return handler.invokeAsync(params, context);
    }
}
