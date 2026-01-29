/**
 * @program: anp4java
 * @author: Ruitao.Zhai
 * @date: 2025-01-29
 */
package com.agentconnect.test;

import com.agentconnect.protocol.JsonRpc;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for JsonRpc - request/response serialization and error codes.
 */
@DisplayName("JsonRpc Tests")
class JsonRpcTest {

    private static final ObjectMapper objectMapper = new ObjectMapper();

    @Nested
    @DisplayName("Request Tests")
    class RequestTests {

        @Test
        @DisplayName("should create request with method and params")
        void testCreateRequest() {
            Map<String, Object> params = new HashMap<>();
            params.put("query", "Tokyo");
            params.put("limit", 10);

            JsonRpc.Request request = JsonRpc.Request.create("search", params);

            assertEquals("2.0", request.getJsonrpc());
            assertEquals("search", request.getMethod());
            assertEquals(params, request.getParams());
            assertNotNull(request.getId());
        }

        @Test
        @DisplayName("should create request with method only")
        void testCreateRequestMethodOnly() {
            JsonRpc.Request request = JsonRpc.Request.create("ping");

            assertEquals("2.0", request.getJsonrpc());
            assertEquals("ping", request.getMethod());
            assertNotNull(request.getParams());
            assertTrue(request.getParams().isEmpty());
            assertNotNull(request.getId());
        }

        @Test
        @DisplayName("should generate unique IDs for each request")
        void testUniqueIds() {
            JsonRpc.Request request1 = JsonRpc.Request.create("method1");
            JsonRpc.Request request2 = JsonRpc.Request.create("method2");

            assertNotEquals(request1.getId(), request2.getId());
        }

        @Test
        @DisplayName("should validate valid request")
        void testValidRequest() {
            JsonRpc.Request request = JsonRpc.Request.create("search");
            assertTrue(request.isValid());
        }

        @Test
        @DisplayName("should invalidate request with wrong version")
        void testInvalidVersion() {
            JsonRpc.Request request = new JsonRpc.Request();
            request.setJsonrpc("1.0");
            request.setMethod("search");

            assertFalse(request.isValid());
        }

        @Test
        @DisplayName("should invalidate request with null method")
        void testNullMethod() {
            JsonRpc.Request request = new JsonRpc.Request();
            request.setJsonrpc("2.0");
            request.setMethod(null);

            assertFalse(request.isValid());
        }

        @Test
        @DisplayName("should invalidate request with empty method")
        void testEmptyMethod() {
            JsonRpc.Request request = new JsonRpc.Request();
            request.setJsonrpc("2.0");
            request.setMethod("");

            assertFalse(request.isValid());
        }

        @Test
        @DisplayName("should serialize to JSON correctly")
        void testSerialization() throws Exception {
            Map<String, Object> params = new HashMap<>();
            params.put("query", "Tokyo");

            JsonRpc.Request request = new JsonRpc.Request("search", params, "req-123");

            String json = objectMapper.writeValueAsString(request);
            
            assertTrue(json.contains("\"jsonrpc\":\"2.0\""));
            assertTrue(json.contains("\"method\":\"search\""));
            assertTrue(json.contains("\"id\":\"req-123\""));
            assertTrue(json.contains("\"query\":\"Tokyo\""));
        }

        @Test
        @DisplayName("should deserialize from JSON correctly")
        void testDeserialization() throws Exception {
            String json = "{\"jsonrpc\":\"2.0\",\"method\":\"search\",\"params\":{\"query\":\"Tokyo\"},\"id\":\"req-123\"}";

            JsonRpc.Request request = objectMapper.readValue(json, JsonRpc.Request.class);

            assertEquals("2.0", request.getJsonrpc());
            assertEquals("search", request.getMethod());
            assertEquals("Tokyo", request.getParams().get("query"));
            assertEquals("req-123", request.getId());
        }

        @Test
        @DisplayName("should have meaningful toString")
        void testToString() {
            JsonRpc.Request request = new JsonRpc.Request("search", null, "req-123");
            String str = request.toString();

            assertTrue(str.contains("search"));
            assertTrue(str.contains("req-123"));
        }
    }

    @Nested
    @DisplayName("Response Tests")
    class ResponseTests {

        @Test
        @DisplayName("should create success response")
        void testSuccessResponse() {
            Map<String, Object> result = new HashMap<>();
            result.put("status", "ok");
            result.put("count", 5);

            JsonRpc.Response response = JsonRpc.Response.success(result, "req-123");

            assertEquals("2.0", response.getJsonrpc());
            assertEquals(result, response.getResult());
            assertNull(response.getError());
            assertEquals("req-123", response.getId());
            assertTrue(response.isSuccess());
        }

        @Test
        @DisplayName("should create error response")
        void testErrorResponse() {
            JsonRpc.Error error = new JsonRpc.Error(-32601, "Method not found");

            JsonRpc.Response response = JsonRpc.Response.error(error, "req-123");

            assertEquals("2.0", response.getJsonrpc());
            assertNull(response.getResult());
            assertEquals(error, response.getError());
            assertEquals("req-123", response.getId());
            assertFalse(response.isSuccess());
        }

        @Test
        @DisplayName("should serialize success response correctly")
        void testSuccessResponseSerialization() throws Exception {
            Map<String, Object> result = new HashMap<>();
            result.put("data", "test");

            JsonRpc.Response response = JsonRpc.Response.success(result, "req-123");
            String json = objectMapper.writeValueAsString(response);

            assertTrue(json.contains("\"jsonrpc\":\"2.0\""));
            assertTrue(json.contains("\"result\""));
            assertTrue(json.contains("\"data\":\"test\""));
            assertFalse(json.contains("\"error\""));
        }

        @Test
        @DisplayName("should serialize error response correctly")
        void testErrorResponseSerialization() throws Exception {
            JsonRpc.Error error = new JsonRpc.Error(-32601, "Method not found");
            JsonRpc.Response response = JsonRpc.Response.error(error, "req-123");
            String json = objectMapper.writeValueAsString(response);

            assertTrue(json.contains("\"jsonrpc\":\"2.0\""));
            assertTrue(json.contains("\"error\""));
            assertTrue(json.contains("-32601"));
            assertFalse(json.contains("\"result\""));
        }

        @Test
        @DisplayName("should have meaningful toString for success")
        void testSuccessToString() {
            JsonRpc.Response response = JsonRpc.Response.success("result-data", "req-123");
            String str = response.toString();

            assertTrue(str.contains("result"));
            assertTrue(str.contains("req-123"));
        }

        @Test
        @DisplayName("should have meaningful toString for error")
        void testErrorToString() {
            JsonRpc.Error error = new JsonRpc.Error(-32601, "Method not found");
            JsonRpc.Response response = JsonRpc.Response.error(error, "req-123");
            String str = response.toString();

            assertTrue(str.contains("error"));
            assertTrue(str.contains("req-123"));
        }
    }

    @Nested
    @DisplayName("Error Tests")
    class ErrorTests {

        @Test
        @DisplayName("should create error with code and message")
        void testCreateError() {
            JsonRpc.Error error = new JsonRpc.Error(-32600, "Invalid Request");

            assertEquals(-32600, error.getCode());
            assertEquals("Invalid Request", error.getMessage());
            assertNull(error.getData());
        }

        @Test
        @DisplayName("should create error with data")
        void testCreateErrorWithData() {
            Map<String, Object> data = new HashMap<>();
            data.put("field", "query");
            data.put("reason", "required");

            JsonRpc.Error error = new JsonRpc.Error(-32602, "Invalid params", data);

            assertEquals(-32602, error.getCode());
            assertEquals("Invalid params", error.getMessage());
            assertEquals(data, error.getData());
        }

        @Test
        @DisplayName("should create parse error")
        void testParseError() {
            JsonRpc.Error error = JsonRpc.Error.parseError("Invalid JSON");

            assertEquals(JsonRpc.PARSE_ERROR, error.getCode());
            assertEquals("Invalid JSON", error.getMessage());
        }

        @Test
        @DisplayName("should create parse error with default message")
        void testParseErrorDefault() {
            JsonRpc.Error error = JsonRpc.Error.parseError(null);

            assertEquals(JsonRpc.PARSE_ERROR, error.getCode());
            assertEquals("Parse error", error.getMessage());
        }

        @Test
        @DisplayName("should create invalid request error")
        void testInvalidRequestError() {
            JsonRpc.Error error = JsonRpc.Error.invalidRequest("Missing method");

            assertEquals(JsonRpc.INVALID_REQUEST, error.getCode());
            assertEquals("Missing method", error.getMessage());
        }

        @Test
        @DisplayName("should create method not found error")
        void testMethodNotFoundError() {
            JsonRpc.Error error = JsonRpc.Error.methodNotFound("unknownMethod");

            assertEquals(JsonRpc.METHOD_NOT_FOUND, error.getCode());
            assertTrue(error.getMessage().contains("unknownMethod"));
        }

        @Test
        @DisplayName("should create invalid params error")
        void testInvalidParamsError() {
            JsonRpc.Error error = JsonRpc.Error.invalidParams("Missing required parameter: query");

            assertEquals(JsonRpc.INVALID_PARAMS, error.getCode());
            assertTrue(error.getMessage().contains("query"));
        }

        @Test
        @DisplayName("should create internal error")
        void testInternalError() {
            JsonRpc.Error error = JsonRpc.Error.internalError("Database connection failed");

            assertEquals(JsonRpc.INTERNAL_ERROR, error.getCode());
            assertTrue(error.getMessage().contains("Database"));
        }

        @Test
        @DisplayName("should create authentication error")
        void testAuthenticationError() {
            JsonRpc.Error error = JsonRpc.Error.authenticationError("Invalid token");

            assertEquals(JsonRpc.AUTHENTICATION_ERROR, error.getCode());
            assertEquals("Invalid token", error.getMessage());
        }

        @Test
        @DisplayName("should create authorization error")
        void testAuthorizationError() {
            JsonRpc.Error error = JsonRpc.Error.authorizationError("Insufficient permissions");

            assertEquals(JsonRpc.AUTHORIZATION_ERROR, error.getCode());
            assertEquals("Insufficient permissions", error.getMessage());
        }

        @Test
        @DisplayName("should have meaningful toString")
        void testErrorToString() {
            JsonRpc.Error error = new JsonRpc.Error(-32601, "Method not found");
            String str = error.toString();

            assertTrue(str.contains("-32601"));
            assertTrue(str.contains("Method not found"));
        }
    }

    @Nested
    @DisplayName("Error Code Constants Tests")
    class ErrorCodeConstantsTests {

        @Test
        @DisplayName("should have correct standard error codes")
        void testStandardErrorCodes() {
            assertEquals(-32700, JsonRpc.PARSE_ERROR);
            assertEquals(-32600, JsonRpc.INVALID_REQUEST);
            assertEquals(-32601, JsonRpc.METHOD_NOT_FOUND);
            assertEquals(-32602, JsonRpc.INVALID_PARAMS);
            assertEquals(-32603, JsonRpc.INTERNAL_ERROR);
        }

        @Test
        @DisplayName("should have correct custom error codes")
        void testCustomErrorCodes() {
            assertEquals(-32001, JsonRpc.AUTHENTICATION_ERROR);
            assertEquals(-32002, JsonRpc.AUTHORIZATION_ERROR);
            assertEquals(-32003, JsonRpc.RATE_LIMIT_ERROR);
            assertEquals(-32004, JsonRpc.VALIDATION_ERROR);
            assertEquals(-32005, JsonRpc.RESOURCE_NOT_FOUND);
            assertEquals(-32006, JsonRpc.CONFLICT_ERROR);
            assertEquals(-32007, JsonRpc.SERVICE_UNAVAILABLE);
        }

        @Test
        @DisplayName("should have correct version constant")
        void testVersionConstant() {
            assertEquals("2.0", JsonRpc.VERSION);
        }
    }

    @Nested
    @DisplayName("RpcException Tests")
    class RpcExceptionTests {

        @Test
        @DisplayName("should create exception from error")
        void testCreateFromError() {
            JsonRpc.Error error = new JsonRpc.Error(-32601, "Method not found");
            JsonRpc.RpcException exception = new JsonRpc.RpcException(error);

            assertEquals(error, exception.getError());
            assertEquals(-32601, exception.getCode());
            assertEquals("Method not found", exception.getMessage());
        }

        @Test
        @DisplayName("should create exception with code and message")
        void testCreateWithCodeAndMessage() {
            JsonRpc.RpcException exception = new JsonRpc.RpcException(-32602, "Invalid params");

            assertEquals(-32602, exception.getCode());
            assertEquals("Invalid params", exception.getMessage());
            assertNotNull(exception.getError());
        }

        @Test
        @DisplayName("should create exception with code, message, and data")
        void testCreateWithData() {
            Map<String, Object> data = new HashMap<>();
            data.put("field", "query");

            JsonRpc.RpcException exception = new JsonRpc.RpcException(-32602, "Invalid params", data);

            assertEquals(-32602, exception.getCode());
            assertEquals(data, exception.getError().getData());
        }

        @Test
        @DisplayName("should be throwable")
        void testThrowable() {
            assertThrows(JsonRpc.RpcException.class, () -> {
                throw new JsonRpc.RpcException(-32601, "Method not found");
            });
        }

        @Test
        @DisplayName("should be catchable as RuntimeException")
        void testCatchableAsRuntimeException() {
            try {
                throw new JsonRpc.RpcException(-32601, "Method not found");
            } catch (RuntimeException e) {
                assertTrue(e instanceof JsonRpc.RpcException);
            }
        }
    }
}
