/**
 * @program: anp4java
 * @description: ANP 全局异常处理器
 * @author: Ruitao.Zhai
 * @date: 2025-01-21
 **/
package com.agentconnect.spring;

import com.agentconnect.protocol.JsonRpc;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseStatus;

/**
 * Global exception handler for ANP Spring Boot integration.
 * 
 * Converts exceptions to JSON-RPC 2.0 error responses with appropriate error codes.
 * All responses use HTTP 200 status code as per JSON-RPC 2.0 specification.
 */
@ControllerAdvice
public class AnpExceptionHandler {
    
    private static final Logger log = LoggerFactory.getLogger(AnpExceptionHandler.class);
    private static final ObjectMapper objectMapper = new ObjectMapper();
    
    /**
     * Handle JsonRpc.RpcException - preserves the original error code and message.
     * 
     * @param ex the RpcException
     * @return JSON-RPC error response with HTTP 200
     */
    @ExceptionHandler(JsonRpc.RpcException.class)
    @ResponseStatus(HttpStatus.OK)
    public ResponseEntity<String> handleJsonRpcException(JsonRpc.RpcException ex) {
        log.warn("JSON-RPC exception: code={}, message={}", ex.getCode(), ex.getMessage());
        
        JsonRpc.Error error = ex.getError();
        JsonRpc.Response response = JsonRpc.Response.error(error, null);
        
        return ResponseEntity
            .ok()
            .contentType(MediaType.APPLICATION_JSON)
            .body(serializeResponse(response));
    }
    
    /**
     * Handle IllegalArgumentException - maps to JSON-RPC INVALID_PARAMS error.
     * 
     * @param ex the IllegalArgumentException
     * @return JSON-RPC error response with code -32602
     */
    @ExceptionHandler(IllegalArgumentException.class)
    @ResponseStatus(HttpStatus.OK)
    public ResponseEntity<String> handleIllegalArgumentException(IllegalArgumentException ex) {
        log.warn("Invalid argument: {}", ex.getMessage());
        
        JsonRpc.Error error = new JsonRpc.Error(
            JsonRpc.INVALID_PARAMS,
            ex.getMessage() != null ? ex.getMessage() : "Invalid params"
        );
        JsonRpc.Response response = JsonRpc.Response.error(error, null);
        
        return ResponseEntity
            .ok()
            .contentType(MediaType.APPLICATION_JSON)
            .body(serializeResponse(response));
    }
    
    /**
     * Handle NoSuchMethodException - maps to JSON-RPC METHOD_NOT_FOUND error.
     * 
     * @param ex the NoSuchMethodException
     * @return JSON-RPC error response with code -32601
     */
    @ExceptionHandler(NoSuchMethodException.class)
    @ResponseStatus(HttpStatus.OK)
    public ResponseEntity<String> handleNoSuchMethodException(NoSuchMethodException ex) {
        log.warn("Method not found: {}", ex.getMessage());
        
        JsonRpc.Error error = new JsonRpc.Error(
            JsonRpc.METHOD_NOT_FOUND,
            ex.getMessage() != null ? ex.getMessage() : "Method not found"
        );
        JsonRpc.Response response = JsonRpc.Response.error(error, null);
        
        return ResponseEntity
            .ok()
            .contentType(MediaType.APPLICATION_JSON)
            .body(serializeResponse(response));
    }
    
    /**
     * Handle RuntimeException - maps to JSON-RPC SERVER_ERROR.
     * 
     * @param ex the RuntimeException
     * @return JSON-RPC error response with code -32000
     */
    @ExceptionHandler(RuntimeException.class)
    @ResponseStatus(HttpStatus.OK)
    public ResponseEntity<String> handleRuntimeException(RuntimeException ex) {
        log.error("Runtime exception occurred", ex);
        
        JsonRpc.Error error = new JsonRpc.Error(
            -32000,  // Server error
            ex.getMessage() != null ? ex.getMessage() : "Server error"
        );
        JsonRpc.Response response = JsonRpc.Response.error(error, null);
        
        return ResponseEntity
            .ok()
            .contentType(MediaType.APPLICATION_JSON)
            .body(serializeResponse(response));
    }
    
    /**
     * Handle generic Exception - maps to JSON-RPC INTERNAL_ERROR.
     * 
     * @param ex the Exception
     * @return JSON-RPC error response with code -32603
     */
    @ExceptionHandler(Exception.class)
    @ResponseStatus(HttpStatus.OK)
    public ResponseEntity<String> handleException(Exception ex) {
        log.error("Unexpected exception occurred", ex);
        
        JsonRpc.Error error = new JsonRpc.Error(
            JsonRpc.INTERNAL_ERROR,
            ex.getMessage() != null ? ex.getMessage() : "Internal error"
        );
        JsonRpc.Response response = JsonRpc.Response.error(error, null);
        
        return ResponseEntity
            .ok()
            .contentType(MediaType.APPLICATION_JSON)
            .body(serializeResponse(response));
    }
    
    /**
     * Serialize JSON-RPC response to JSON string.
     * 
     * @param response the JSON-RPC response
     * @return JSON string representation
     */
    private String serializeResponse(JsonRpc.Response response) {
        try {
            return objectMapper.writeValueAsString(response);
        } catch (Exception e) {
            log.error("Failed to serialize response", e);
            // Fallback to minimal JSON-RPC error response
            return "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32603,\"message\":\"Internal error\"},\"id\":null}";
        }
    }
}
