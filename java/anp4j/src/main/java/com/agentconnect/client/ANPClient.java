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
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
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
    private static final ObjectMapper objectMapper = new ObjectMapper();
    private static final Duration DEFAULT_TIMEOUT = Duration.ofSeconds(30);
    
    private final DIDWbaAuthHeader authHeader;
    private final HttpClient httpClient;
    private final Duration timeout;
    
    /**
     * Create an ANP client without DID authentication (for local testing).
     */
    public ANPClient() {
        this.authHeader = null;
        this.timeout = DEFAULT_TIMEOUT;
        this.httpClient = HttpClient.newBuilder()
            .connectTimeout(timeout)
            .build();
    }
    
    /**
     * Create an ANP client with DID authentication.
     * 
     * @param didDocumentPath Path to the DID document
     * @param privateKeyPath Path to the private key
     */
    public ANPClient(String didDocumentPath, String privateKeyPath) {
        this(didDocumentPath, privateKeyPath, DEFAULT_TIMEOUT);
    }
    
    /**
     * Create an ANP client with custom timeout.
     */
    public ANPClient(String didDocumentPath, String privateKeyPath, Duration timeout) {
        this.authHeader = new DIDWbaAuthHeader(didDocumentPath, privateKeyPath);
        this.timeout = timeout;
        this.httpClient = HttpClient.newBuilder()
            .connectTimeout(timeout)
            .build();
    }
    
    /**
     * Create an ANP client with existing auth header.
     */
    public ANPClient(DIDWbaAuthHeader authHeader) {
        this(authHeader, DEFAULT_TIMEOUT);
    }
    
    /**
     * Create an ANP client with existing auth header and custom timeout.
     */
    public ANPClient(DIDWbaAuthHeader authHeader, Duration timeout) {
        this.authHeader = authHeader;
        this.timeout = timeout;
        this.httpClient = HttpClient.newBuilder()
            .connectTimeout(timeout)
            .build();
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
        
        HttpRequest.Builder requestBuilder = HttpRequest.newBuilder()
            .uri(URI.create(url))
            .timeout(timeout)
            .GET();
        
        if (authHeader != null) {
            Map<String, String> headers = authHeader.getAuthHeader(url);
            headers.forEach(requestBuilder::header);
        }
        requestBuilder.header("Accept", "application/json");
        
        HttpRequest request = requestBuilder.build();
        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        
        if (authHeader != null) {
            Map<String, String> responseHeaders = new HashMap<>();
            response.headers().map().forEach((k, v) -> {
                if (!v.isEmpty()) {
                    responseHeaders.put(k.toLowerCase(), v.get(0));
                }
            });
            authHeader.updateToken(url, responseHeaders);
        }
        
        if (response.statusCode() >= 400) {
            throw new HttpException(response.statusCode(), response.body(), url);
        }
        
        return objectMapper.readValue(response.body(), new TypeReference<Map<String, Object>>() {});
    }
    
    /**
     * Fetch a URL asynchronously.
     */
    public CompletableFuture<Map<String, Object>> fetchAsync(String url) {
        return CompletableFuture.supplyAsync(() -> {
            try {
                return fetch(url);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        });
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
        
        HttpRequest.Builder requestBuilder = HttpRequest.newBuilder()
            .uri(URI.create(serverUrl))
            .timeout(timeout)
            .POST(HttpRequest.BodyPublishers.ofString(requestBody));
        
        if (authHeader != null) {
            Map<String, String> headers = authHeader.getAuthHeader(serverUrl);
            headers.forEach(requestBuilder::header);
        }
        requestBuilder.header("Content-Type", "application/json");
        requestBuilder.header("Accept", "application/json");
        
        HttpRequest request = requestBuilder.build();
        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        
        if (authHeader != null) {
            Map<String, String> responseHeaders = new HashMap<>();
            response.headers().map().forEach((k, v) -> {
                if (!v.isEmpty()) {
                    responseHeaders.put(k.toLowerCase(), v.get(0));
                }
            });
            authHeader.updateToken(serverUrl, responseHeaders);
        }
        
        if (response.statusCode() >= 400) {
            throw new HttpException(response.statusCode(), response.body(), serverUrl);
        }
        
        Map<String, Object> responseJson = objectMapper.readValue(
            response.body(), 
            new TypeReference<Map<String, Object>>() {}
        );
        
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
        return CompletableFuture.supplyAsync(() -> {
            try {
                return callJsonRpc(serverUrl, method, params);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        });
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
