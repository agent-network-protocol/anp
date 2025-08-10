package com.agentconnect.test.example;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.hc.client5.http.async.methods.*;
import org.apache.hc.client5.http.impl.async.CloseableHttpAsyncClient;
import org.apache.hc.client5.http.impl.async.HttpAsyncClients;
import org.apache.hc.core5.http.ContentType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Future;

public class HttpClientUtils {
    
    private static final Logger logger = LoggerFactory.getLogger(HttpClientUtils.class);
    private static final ObjectMapper objectMapper = new ObjectMapper();
    private static CloseableHttpAsyncClient httpClient;
    
    static {
        httpClient = HttpAsyncClients.createDefault();
        httpClient.start();
    }
    
    /**
     * Upload JSON data using PUT request
     */
    public static CompletableFuture<Boolean> uploadJson(String url, Object data) {
        return CompletableFuture.supplyAsync(() -> {
            try {
                String jsonString = objectMapper.writeValueAsString(data);
                
                SimpleHttpRequest request = SimpleRequestBuilder.put(url)
                    .setHeader("Content-Type", "application/json")
                    .setBody(jsonString, ContentType.APPLICATION_JSON)
                    .build();
                
                Future<SimpleHttpResponse> future = httpClient.execute(
                    SimpleRequestProducer.create(request),
                    SimpleResponseConsumer.create(),
                    null
                );
                
                SimpleHttpResponse response = future.get();
                boolean success = response.getCode() == 200;
                
                if (success) {
                    logger.info("Successfully uploaded data to: {}", url);
                } else {
                    logger.error("Failed to upload data to: {}, status: {}", url, response.getCode());
                }
                
                return success;
                
            } catch (Exception e) {
                logger.error("Failed to upload data to: {}", url, e);
                return false;
            }
        });
    }
    
    /**
     * Download JSON data using GET request
     */
    public static CompletableFuture<Map<String, Object>> downloadJson(String url) {
        return CompletableFuture.supplyAsync(() -> {
            try {
                SimpleHttpRequest request = SimpleRequestBuilder.get(url).build();
                
                Future<SimpleHttpResponse> future = httpClient.execute(
                    SimpleRequestProducer.create(request),
                    SimpleResponseConsumer.create(),
                    null
                );
                
                SimpleHttpResponse response = future.get();
                
                if (response.getCode() == 200) {
                    String jsonString = response.getBodyText();
                    @SuppressWarnings("unchecked")
                    Map<String, Object> result = objectMapper.readValue(jsonString, Map.class);
                    logger.info("Successfully downloaded data from: {}", url);
                    return result;
                } else {
                    logger.warn("Failed to download data from: {}, status: {}", url, response.getCode());
                    return null;
                }
                
            } catch (Exception e) {
                logger.error("Failed to download data from: {}", url, e);
                return null;
            }
        });
    }
    
    /**
     * Send GET request with custom headers
     */
    public static CompletableFuture<HttpResult> sendGetWithHeaders(String url, Map<String, String> headers) {
        return CompletableFuture.supplyAsync(() -> {
            try {
                SimpleRequestBuilder builder = SimpleRequestBuilder.get(url);
                
                // Add custom headers
                if (headers != null) {
                    headers.forEach(builder::setHeader);
                }
                
                SimpleHttpRequest request = builder.build();
                
                Future<SimpleHttpResponse> future = httpClient.execute(
                    SimpleRequestProducer.create(request),
                    SimpleResponseConsumer.create(),
                    null
                );
                
                SimpleHttpResponse response = future.get();
                
                // Extract response headers
                Map<String, String> responseHeaders = new java.util.HashMap<>();
                response.headerIterator().forEachRemaining(header -> 
                    responseHeaders.put(header.getName(), header.getValue())
                );
                
                return new HttpResult(response.getCode(), responseHeaders, response.getBodyText());
                
            } catch (Exception e) {
                logger.error("Failed to send GET request to: {}", url, e);
                return new HttpResult(500, Map.of(), "");
            }
        });
    }
    
    /**
     * Convert URL for local testing
     */
    public static String convertUrlForLocalTesting(String url, boolean isLocalTesting, String serverDomain) {
        if (isLocalTesting) {
            url = url.replace("https://", "http://");
            url = url.replace(serverDomain, "127.0.0.1:9000");
        }
        return url;
    }
    
    /**
     * Close the HTTP client
     */
    public static void close() {
        try {
            if (httpClient != null) {
                httpClient.close();
            }
        } catch (Exception e) {
            logger.error("Error closing HTTP client", e);
        }
    }
    
    /**
     * HTTP Result container
     */
    public static class HttpResult {
        private final int statusCode;
        private final Map<String, String> headers;
        private final String body;
        
        public HttpResult(int statusCode, Map<String, String> headers, String body) {
            this.statusCode = statusCode;
            this.headers = headers;
            this.body = body;
        }
        
        public int getStatusCode() { return statusCode; }
        public Map<String, String> getHeaders() { return headers; }
        public String getBody() { return body; }
        public boolean isSuccess() { return statusCode == 200; }
    }
}