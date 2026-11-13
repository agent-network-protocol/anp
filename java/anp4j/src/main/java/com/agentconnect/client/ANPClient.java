/**
 * @program: anp4java
 * @author: Ruitao.Zhai
 * @date: 2025-01-29
 */
package com.agentconnect.client;

import com.agentconnect.authentication.DIDWbaAuthHeader;
import com.agentconnect.protocol.JsonRpc;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.URI;
import java.time.Duration;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.CompletableFuture;

/**
 * ANP HTTP Client with DID-WBA authentication.
 * 
 * Provides authenticated HTTP requests for fetching ANP documents and calling JSON-RPC endpoints.
 * 
 * Example:
 *     ANPClient client = new ANPClient(
 *         "/path/to/did-doc.json",
 *         "/path/to/private-key.pem"
 *     );
 *     
 *     // Fetch ad.json
 *     Map<String, Object> ad = client.fetch("https://hotel.example.com/ad.json");
 *     
 *     // Call JSON-RPC method
 *     Object result = client.callJsonRpc(
 *         "https://hotel.example.com/rpc",
 *         "search",
 *         Map.of("query", "Tokyo")
 *     );
 */
public class ANPClient {
    
    private static final Logger logger = LoggerFactory.getLogger(ANPClient.class);
    private static final ObjectMapper objectMapper = new ObjectMapper().enable(com.fasterxml.jackson.core.JsonParser.Feature.STRICT_DUPLICATE_DETECTION).enable(com.fasterxml.jackson.databind.DeserializationFeature.FAIL_ON_TRAILING_TOKENS);
    private static final Duration DEFAULT_TIMEOUT = Duration.ofSeconds(30);
    
    private final DIDWbaAuthHeader authHeader;
    private final com.agentconnect.authentication.PublicHttpTransport.Transport transport;
    private final java.util.Set<String> authenticatedOrigins;
    private final URI trustedBase;

    public ANPClient() { this((DIDWbaAuthHeader)null,DEFAULT_TIMEOUT); }
    public ANPClient(String didDocumentPath,String privateKeyPath) { this(didDocumentPath,privateKeyPath,DEFAULT_TIMEOUT); }
    public ANPClient(String didDocumentPath,String privateKeyPath,Duration timeout) { this(new DIDWbaAuthHeader(didDocumentPath,privateKeyPath),timeout); }
    public ANPClient(DIDWbaAuthHeader authHeader) { this(authHeader,DEFAULT_TIMEOUT); }
    public ANPClient(DIDWbaAuthHeader authHeader,Duration timeout) { this(authHeader,timeout,java.util.Set.of(),null,null); }

    /** Host-only policy: discovery is unsigned unless an origin is approved. */
    public ANPClient(DIDWbaAuthHeader authHeader,Duration timeout,java.util.Set<String> authenticatedOrigins,
            URI trustedBase,com.agentconnect.authentication.PublicHttpTransport.Transport transport) {
        this.authHeader=authHeader;this.trustedBase=trustedBase;
        this.authenticatedOrigins=authenticatedOrigins.stream().map(URI::create)
            .map(com.agentconnect.authentication.PublicNetworkPolicy::origin).collect(java.util.stream.Collectors.toUnmodifiableSet());
        this.transport=transport!=null?transport:new com.agentconnect.authentication.PublicHttpTransport(trustedBase,timeout).asTransport();
    }

    private Map<String,Object> requestJson(String raw,String method,byte[] body) throws IOException {
        URI uri=URI.create(raw);
        com.agentconnect.authentication.PublicNetworkPolicy.validate(uri,trustedBase);
        String origin=com.agentconnect.authentication.PublicNetworkPolicy.origin(uri);
        boolean authenticate=authenticatedOrigins.contains(origin);
        if(authenticate&&authHeader==null)throw new SecurityException("Approved authenticated origin requires credentials");
        Map<String,String> headers=new HashMap<>();
        if(body.length>0)headers.put("Content-Type","application/json");
        if(authenticate)headers.putAll(authHeader.getAuthHeader(raw));
        var response=transport.request(uri,method,headers,body);
        if(response.status()!=200)throw new HttpException(response.status(),"Request rejected",raw);
        if(authenticate)authHeader.updateToken(raw,response.authenticationHeaders());
        return objectMapper.readValue(response.body(),new TypeReference<Map<String,Object>>(){});
    }

    /**
     * Fetch a URL with authentication.
     * 
     * @param url The URL to fetch
     * @return Response as Map
     * @throws IOException If the request fails
     */
    public Map<String, Object> fetch(String url) throws IOException, InterruptedException {
        logger.debug("Fetching URL: {}", url);
        
        return requestJson(url,"GET",new byte[0]);
    }
    
    /**
     * Fetch a URL asynchronously.
     */
    public CompletableFuture<Map<String, Object>> fetchAsync(String url) {
        return com.agentconnect.authentication.PublicHttpTransport.async(() -> {
            try {
                return fetch(url);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }, DEFAULT_TIMEOUT);
    }
    
    /**
     * Call a JSON-RPC method.
     * 
     * @param serverUrl The JSON-RPC endpoint URL
     * @param method The method name
     * @param params The method parameters
     * @return The result
     * @throws IOException If the request fails
     */
    public Object callJsonRpc(String serverUrl, String method, Map<String, Object> params) 
            throws IOException, InterruptedException {
        
        logger.debug("Calling JSON-RPC method {} at {}", method, serverUrl);
        
        JsonRpc.Request rpcRequest = JsonRpc.Request.create(method, params);
        String requestBody = objectMapper.writeValueAsString(rpcRequest);
        
        Map<String,Object> responseJson=requestJson(serverUrl,"POST",requestBody.getBytes(java.nio.charset.StandardCharsets.UTF_8));

        if (responseJson.containsKey("error") && responseJson.get("error") != null) {
            @SuppressWarnings("unchecked")
            Map<String, Object> errorMap = (Map<String, Object>) responseJson.get("error");
            int code = errorMap.containsKey("code") ? ((Number) errorMap.get("code")).intValue() : JsonRpc.INTERNAL_ERROR;
            String message = (String) errorMap.getOrDefault("message", "Unknown error");
            Object data = errorMap.get("data");
            throw new RpcException(code, message, data);
        }
        
        return responseJson.get("result");
    }
    
    /**
     * Call JSON-RPC asynchronously.
     */
    public CompletableFuture<Object> callJsonRpcAsync(String serverUrl, String method, Map<String, Object> params) {
        return com.agentconnect.authentication.PublicHttpTransport.async(() -> {
            try {
                return callJsonRpc(serverUrl, method, params);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }, DEFAULT_TIMEOUT);
    }
    
    /**
     * Get the auth header instance.
     */
    public DIDWbaAuthHeader getAuthHeader() {
        return authHeader;
    }
    
    /**
     * HTTP exception.
     */
    public static class HttpException extends IOException {
        private final int statusCode;
        private final String url;
        
        public HttpException(int statusCode, String message, String url) {
            super("HTTP " + statusCode + ": " + message + " (" + url + ")");
            this.statusCode = statusCode;
            this.url = url;
        }
        
        public int getStatusCode() {
            return statusCode;
        }
        
        public String getUrl() {
            return url;
        }
    }
    
    /**
     * RPC exception.
     */
    public static class RpcException extends RuntimeException {
        private final int code;
        private final Object data;
        
        public RpcException(int code, String message, Object data) {
            super("RPC " + code + ": " + message);
            this.code = code;
            this.data = data;
        }
        
        public int getCode() {
            return code;
        }
        
        public Object getData() {
            return data;
        }
    }
}
