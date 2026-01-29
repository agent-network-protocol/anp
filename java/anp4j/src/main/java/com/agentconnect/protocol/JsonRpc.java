/**
 * @program: anp4java
 * @author: Ruitao.Zhai
 * @date: 2025-01-29
 */
package com.agentconnect.protocol;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;

/**
 * JSON-RPC 2.0 protocol implementation.
 * 
 * Provides request, response, and error classes following the JSON-RPC 2.0 specification.
 */
public final class JsonRpc {
    
    public static final String VERSION = "2.0";
    
    // Standard error codes
    public static final int PARSE_ERROR = -32700;
    public static final int INVALID_REQUEST = -32600;
    public static final int METHOD_NOT_FOUND = -32601;
    public static final int INVALID_PARAMS = -32602;
    public static final int INTERNAL_ERROR = -32603;
    
    // Custom error codes (-32000 to -32099)
    public static final int AUTHENTICATION_ERROR = -32001;
    public static final int AUTHORIZATION_ERROR = -32002;
    public static final int RATE_LIMIT_ERROR = -32003;
    public static final int VALIDATION_ERROR = -32004;
    public static final int RESOURCE_NOT_FOUND = -32005;
    public static final int CONFLICT_ERROR = -32006;
    public static final int SERVICE_UNAVAILABLE = -32007;
    
    private JsonRpc() {}
    
    /**
     * JSON-RPC 2.0 Request
     */
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public static class Request {
        @JsonProperty("jsonrpc")
        private String jsonrpc = VERSION;
        
        @JsonProperty("method")
        private String method;
        
        @JsonProperty("params")
        private Map<String, Object> params;
        
        @JsonProperty("id")
        private Object id;
        
        public Request() {}
        
        public Request(String method, Map<String, Object> params, Object id) {
            this.method = method;
            this.params = params;
            this.id = id;
        }
        
        public static Request create(String method, Map<String, Object> params) {
            return new Request(method, params, UUID.randomUUID().toString());
        }
        
        public static Request create(String method) {
            return create(method, new HashMap<>());
        }
        
        public String getJsonrpc() { return jsonrpc; }
        public String getMethod() { return method; }
        public Map<String, Object> getParams() { return params; }
        public Object getId() { return id; }
        
        public void setJsonrpc(String jsonrpc) { this.jsonrpc = jsonrpc; }
        public void setMethod(String method) { this.method = method; }
        public void setParams(Map<String, Object> params) { this.params = params; }
        public void setId(Object id) { this.id = id; }
        
        /**
         * Validate request format
         */
        @JsonIgnore
        public boolean isValid() {
            return VERSION.equals(jsonrpc) && method != null && !method.isEmpty();
        }
        
        @Override
        public String toString() {
            return "Request{method='" + method + "', id=" + id + "}";
        }
    }
    
    /**
     * JSON-RPC 2.0 Response
     */
    @JsonInclude(JsonInclude.Include.NON_NULL)
    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class Response {
        @JsonProperty("jsonrpc")
        private String jsonrpc = VERSION;
        
        @JsonProperty("result")
        private Object result;
        
        @JsonProperty("error")
        private Error error;
        
        @JsonProperty("id")
        private Object id;
        
        public Response() {}
        
        private Response(Object result, Error error, Object id) {
            this.result = result;
            this.error = error;
            this.id = id;
        }
        
        public static Response success(Object result, Object id) {
            return new Response(result, null, id);
        }
        
        public static Response error(Error error, Object id) {
            return new Response(null, error, id);
        }
        
        public String getJsonrpc() { return jsonrpc; }
        public Object getResult() { return result; }
        public Error getError() { return error; }
        public Object getId() { return id; }
        
        public void setJsonrpc(String jsonrpc) { this.jsonrpc = jsonrpc; }
        public void setResult(Object result) { this.result = result; }
        public void setError(Error error) { this.error = error; }
        public void setId(Object id) { this.id = id; }
        
        @JsonIgnore
        public boolean isSuccess() {
            return error == null;
        }
        
        @Override
        public String toString() {
            if (isSuccess()) {
                return "Response{result=" + result + ", id=" + id + "}";
            } else {
                return "Response{error=" + error + ", id=" + id + "}";
            }
        }
    }
    
    /**
     * JSON-RPC 2.0 Error
     */
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public static class Error {
        @JsonProperty("code")
        private int code;
        
        @JsonProperty("message")
        private String message;
        
        @JsonProperty("data")
        private Object data;
        
        public Error() {}
        
        public Error(int code, String message) {
            this.code = code;
            this.message = message;
        }
        
        public Error(int code, String message, Object data) {
            this.code = code;
            this.message = message;
            this.data = data;
        }
        
        public int getCode() { return code; }
        public String getMessage() { return message; }
        public Object getData() { return data; }
        
        public void setCode(int code) { this.code = code; }
        public void setMessage(String message) { this.message = message; }
        public void setData(Object data) { this.data = data; }
        
        // Factory methods for standard errors
        public static Error parseError(String message) {
            return new Error(PARSE_ERROR, message != null ? message : "Parse error");
        }
        
        public static Error invalidRequest(String message) {
            return new Error(INVALID_REQUEST, message != null ? message : "Invalid Request");
        }
        
        public static Error methodNotFound(String method) {
            return new Error(METHOD_NOT_FOUND, "Method not found: " + method);
        }
        
        public static Error invalidParams(String message) {
            return new Error(INVALID_PARAMS, message != null ? message : "Invalid params");
        }
        
        public static Error internalError(String message) {
            return new Error(INTERNAL_ERROR, message != null ? message : "Internal error");
        }
        
        public static Error authenticationError(String message) {
            return new Error(AUTHENTICATION_ERROR, message != null ? message : "Authentication failed");
        }
        
        public static Error authorizationError(String message) {
            return new Error(AUTHORIZATION_ERROR, message != null ? message : "Authorization denied");
        }
        
        @Override
        public String toString() {
            return "Error{code=" + code + ", message='" + message + "'}";
        }
    }
    
    /**
     * Exception wrapper for RPC errors
     */
    public static class RpcException extends RuntimeException {
        private final Error error;
        
        public RpcException(Error error) {
            super(error.getMessage());
            this.error = error;
        }
        
        public RpcException(int code, String message) {
            this(new Error(code, message));
        }
        
        public RpcException(int code, String message, Object data) {
            this(new Error(code, message, data));
        }
        
        public Error getError() {
            return error;
        }
        
        public int getCode() {
            return error.getCode();
        }
    }
}
