/**
 * @program: anp4java
 * @author: Ruitao.Zhai
 * @date: 2025-01-29
 */
package com.agentconnect.test;

import com.agentconnect.protocol.JsonRpc;
import com.agentconnect.protocol.RPCMethodInfo;
import com.agentconnect.server.AgentHandler;
import com.agentconnect.server.Context;
import com.agentconnect.server.annotation.AnpAgent;
import com.agentconnect.server.annotation.Interface;
import com.agentconnect.server.annotation.Param;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for AgentHandler - annotation scanning and RPC method invocation.
 */
@DisplayName("AgentHandler Tests")
class AgentHandlerTest {

    /**
     * Sample agent for testing.
     */
    @AnpAgent(
        name = "Test Agent",
        did = "did:wba:example.com:test",
        description = "A test agent",
        prefix = "/test",
        tags = {"test", "sample"}
    )
    public static class TestAgent {

        @Interface(description = "Say hello")
        public String hello(String name) {
            return "Hello, " + name + "!";
        }

        @Interface(name = "add", description = "Add two numbers")
        public int add(int a, int b) {
            return a + b;
        }

        @Interface(description = "Get greeting with context")
        public Map<String, Object> greetWithContext(String name, Context ctx) {
            Map<String, Object> result = new HashMap<>();
            result.put("greeting", "Hello, " + name);
            result.put("caller", ctx != null ? ctx.getDid() : "unknown");
            return result;
        }

        @Interface(description = "Echo parameters")
        public Map<String, Object> echo(Map<String, Object> data) {
            return data;
        }

        @Interface(mode = RPCMethodInfo.Mode.LINK, description = "Link mode method")
        public String linkMethod() {
            return "link result";
        }
    }

    /**
     * Agent without annotation for negative testing.
     */
    public static class NonAnnotatedAgent {
        public String hello() {
            return "Hello";
        }
    }

    private AgentHandler handler;
    private TestAgent agent;

    @BeforeEach
    void setUp() {
        agent = new TestAgent();
        handler = new AgentHandler(agent);
    }

    @Nested
    @DisplayName("Initialization Tests")
    class InitializationTests {

        @Test
        @DisplayName("should initialize from annotated agent")
        void testInitialization() {
            assertNotNull(handler);
            assertNotNull(handler.getConfig());
        }

        @Test
        @DisplayName("should extract config from annotation")
        void testConfigExtraction() {
            assertEquals("Test Agent", handler.getConfig().getName());
            assertEquals("did:wba:example.com:test", handler.getConfig().getDid());
            assertEquals("A test agent", handler.getConfig().getDescription());
            assertEquals("/test", handler.getConfig().getPrefix());
        }

        @Test
        @DisplayName("should throw exception for non-annotated agent")
        void testNonAnnotatedAgent() {
            NonAnnotatedAgent nonAnnotated = new NonAnnotatedAgent();
            
            assertThrows(IllegalArgumentException.class, () -> {
                new AgentHandler(nonAnnotated);
            });
        }
    }

    @Nested
    @DisplayName("Method Extraction Tests")
    class MethodExtractionTests {

        @Test
        @DisplayName("should extract all @Interface methods")
        void testMethodExtraction() {
            List<RPCMethodInfo> methods = handler.getMethods();
            
            assertEquals(5, methods.size());
        }

        @Test
        @DisplayName("should extract method names correctly")
        void testMethodNames() {
            List<RPCMethodInfo> methods = handler.getMethods();
            
            List<String> names = methods.stream()
                .map(RPCMethodInfo::getName)
                .toList();
            
            assertTrue(names.contains("hello"));
            assertTrue(names.contains("add"));
            assertTrue(names.contains("greetWithContext"));
            assertTrue(names.contains("echo"));
            assertTrue(names.contains("linkMethod"));
        }

        @Test
        @DisplayName("should use custom name from annotation")
        void testCustomMethodName() {
            List<RPCMethodInfo> methods = handler.getMethods();
            
            // The method is named "add" in annotation, not "addNumbers"
            boolean hasAdd = methods.stream()
                .anyMatch(m -> m.getName().equals("add"));
            
            assertTrue(hasAdd);
        }

        @Test
        @DisplayName("should extract method descriptions")
        void testMethodDescriptions() {
            List<RPCMethodInfo> methods = handler.getMethods();
            
            RPCMethodInfo hello = methods.stream()
                .filter(m -> m.getName().equals("hello"))
                .findFirst()
                .orElseThrow();
            
            assertEquals("Say hello", hello.getDescription());
        }

        @Test
        @DisplayName("should detect context parameter")
        void testContextDetection() {
            List<RPCMethodInfo> methods = handler.getMethods();
            
            RPCMethodInfo greet = methods.stream()
                .filter(m -> m.getName().equals("greetWithContext"))
                .findFirst()
                .orElseThrow();
            
            assertTrue(greet.hasContext());
        }

        @Test
        @DisplayName("should detect link mode")
        void testLinkModeDetection() {
            List<RPCMethodInfo> methods = handler.getMethods();
            
            RPCMethodInfo link = methods.stream()
                .filter(m -> m.getName().equals("linkMethod"))
                .findFirst()
                .orElseThrow();
            
            assertEquals(RPCMethodInfo.Mode.LINK, link.getMode());
        }

        @Test
        @DisplayName("should return unmodifiable methods list")
        void testUnmodifiableMethods() {
            List<RPCMethodInfo> methods = handler.getMethods();
            
            assertThrows(UnsupportedOperationException.class, () -> {
                methods.add(RPCMethodInfo.builder().name("fake").build());
            });
        }
    }

    @Nested
    @DisplayName("RPC Invocation Tests")
    class RpcInvocationTests {

        @Test
        @DisplayName("should invoke method with string parameter")
        void testStringParameter() {
            Map<String, Object> params = new HashMap<>();
            params.put("name", "World");

            Object result = handler.handleRpc("hello", params, null);

            assertEquals("Hello, World!", result);
        }

        @Test
        @DisplayName("should invoke method with integer parameters")
        void testIntegerParameters() {
            Map<String, Object> params = new HashMap<>();
            params.put("a", 5);
            params.put("b", 3);

            Object result = handler.handleRpc("add", params, null);

            assertEquals(8, result);
        }

        @Test
        @DisplayName("should invoke method with context")
        void testWithContext() {
            Map<String, Object> params = new HashMap<>();
            params.put("name", "Alice");

            Context ctx = new Context(
                "did:wba:example.com:caller",
                new Context.Session(),
                null,
                null
            );

            @SuppressWarnings("unchecked")
            Map<String, Object> result = (Map<String, Object>) handler.handleRpc(
                "greetWithContext", params, ctx
            );

            assertEquals("Hello, Alice", result.get("greeting"));
            assertEquals("did:wba:example.com:caller", result.get("caller"));
        }

        @Test
        @DisplayName("should throw RpcException for unknown method")
        void testUnknownMethod() {
            Map<String, Object> params = new HashMap<>();

            JsonRpc.RpcException exception = assertThrows(
                JsonRpc.RpcException.class,
                () -> handler.handleRpc("unknownMethod", params, null)
            );

            assertEquals(JsonRpc.METHOD_NOT_FOUND, exception.getCode());
        }

        @Test
        @DisplayName("should handle null context gracefully")
        void testNullContext() {
            Map<String, Object> params = new HashMap<>();
            params.put("name", "Bob");

            @SuppressWarnings("unchecked")
            Map<String, Object> result = (Map<String, Object>) handler.handleRpc(
                "greetWithContext", params, null
            );

            assertEquals("Hello, Bob", result.get("greeting"));
            assertEquals("unknown", result.get("caller"));
        }
    }

    @Nested
    @DisplayName("JSON-RPC Request Handling Tests")
    class JsonRpcRequestTests {

        @Test
        @DisplayName("should handle valid JSON-RPC request")
        void testValidRequest() {
            Map<String, Object> params = new HashMap<>();
            params.put("name", "World");

            JsonRpc.Request request = new JsonRpc.Request("hello", params, "req-123");
            JsonRpc.Response response = handler.handleRpc(request, null);

            assertTrue(response.isSuccess());
            assertEquals("Hello, World!", response.getResult());
            assertEquals("req-123", response.getId());
        }

        @Test
        @DisplayName("should return error for invalid request")
        void testInvalidRequest() {
            JsonRpc.Request request = new JsonRpc.Request();
            request.setJsonrpc("1.0");  // Invalid version
            request.setMethod("hello");
            request.setId("req-123");

            JsonRpc.Response response = handler.handleRpc(request, null);

            assertFalse(response.isSuccess());
            assertEquals(JsonRpc.INVALID_REQUEST, response.getError().getCode());
        }

        @Test
        @DisplayName("should return error for unknown method")
        void testUnknownMethodRequest() {
            JsonRpc.Request request = JsonRpc.Request.create("unknownMethod");
            JsonRpc.Response response = handler.handleRpc(request, null);

            assertFalse(response.isSuccess());
            assertEquals(JsonRpc.METHOD_NOT_FOUND, response.getError().getCode());
        }

        @Test
        @DisplayName("should preserve request ID in response")
        void testRequestIdPreservation() {
            JsonRpc.Request request = new JsonRpc.Request("hello", 
                Map.of("name", "Test"), "custom-id-456");
            JsonRpc.Response response = handler.handleRpc(request, null);

            assertEquals("custom-id-456", response.getId());
        }
    }

    @Nested
    @DisplayName("Document Generation Tests")
    class DocumentGenerationTests {

        @Test
        @DisplayName("should generate agent description")
        void testAgentDescription() {
            Map<String, Object> ad = handler.getAgentDescription("http://localhost:8080");

            assertEquals("Test Agent", ad.get("name"));
            assertEquals("did:wba:example.com:test", ad.get("did"));
            assertTrue(ad.containsKey("interfaces"));
        }

        @Test
        @DisplayName("should generate OpenRPC document")
        void testOpenRpcDocument() {
            Map<String, Object> openrpc = handler.getOpenRpcDocument(
                "http://localhost:8080/test/rpc"
            );

            assertEquals("1.3.2", openrpc.get("openrpc"));
            assertTrue(openrpc.containsKey("info"));
            assertTrue(openrpc.containsKey("methods"));
        }

        @Test
        @DisplayName("should generate single method document")
        void testSingleMethodDocument() {
            Map<String, Object> doc = handler.getSingleMethodDocument(
                "hello", "http://localhost:8080/test/rpc"
            );

            assertTrue(doc.containsKey("methods"));
            @SuppressWarnings("unchecked")
            List<Map<String, Object>> methods = (List<Map<String, Object>>) doc.get("methods");
            assertEquals(1, methods.size());
            assertEquals("hello", methods.get(0).get("name"));
        }

        @Test
        @DisplayName("should throw exception for unknown method in single doc")
        void testSingleMethodDocUnknown() {
            assertThrows(IllegalArgumentException.class, () -> {
                handler.getSingleMethodDocument("unknownMethod", "http://localhost:8080/rpc");
            });
        }

        @Test
        @DisplayName("should generate OpenAI tools format")
        void testOpenAITools() {
            List<Map<String, Object>> tools = handler.getOpenAITools();

            assertFalse(tools.isEmpty());
            
            Map<String, Object> tool = tools.get(0);
            assertEquals("function", tool.get("type"));
            assertTrue(tool.containsKey("function"));
        }
    }

    @Nested
    @DisplayName("Context Creation Tests")
    class ContextCreationTests {

        @Test
        @DisplayName("should create context with DID")
        void testContextCreation() {
            Context ctx = handler.createContext(
                "did:wba:example.com:caller",
                null,
                null
            );

            assertEquals("did:wba:example.com:caller", ctx.getDid());
            assertNotNull(ctx.getSession());
        }

        @Test
        @DisplayName("should create context with headers")
        void testContextWithHeaders() {
            Map<String, String> headers = new HashMap<>();
            headers.put("Authorization", "Bearer token123");

            Context ctx = handler.createContext(
                "did:wba:example.com:caller",
                null,
                headers
            );

            assertEquals("Bearer token123", ctx.getHeaders().get("Authorization"));
        }
    }
    
    @Nested
    @DisplayName("@Param Annotation Tests")
    class ParamAnnotationTests {
        
        @AnpAgent(name = "Param Test", did = "did:wba:example.com:param-test")
        public static class ParamTestAgent {
            
            @Interface(name = "add", description = "Add two numbers")
            public int add(
                @Param(value = "a", description = "First number") int a,
                @Param(value = "b", description = "Second number") int b
            ) {
                return a + b;
            }
            
            @Interface(name = "greet", description = "Greet with optional title")
            public String greet(
                @Param("name") String name,
                @Param(value = "title", required = false, defaultValue = "\"Mr.\"") String title
            ) {
                return "Hello, " + title + " " + name + "!";
            }
            
            @Interface(name = "calculate", description = "Calculate with context")
            public Map<String, Object> calculate(
                @Param("x") double x,
                @Param("y") double y,
                Context ctx
            ) {
                return Map.of(
                    "sum", x + y,
                    "product", x * y,
                    "caller", ctx != null ? ctx.getDid() : "anonymous"
                );
            }
        }
        
        private AgentHandler paramHandler;
        
        @BeforeEach
        void setUpParamTests() {
            paramHandler = new AgentHandler(new ParamTestAgent());
        }
        
        @Test
        @DisplayName("should invoke method with @Param annotated parameters")
        void testParamAnnotation() {
            Object result = paramHandler.handleRpc("add", Map.of("a", 10, "b", 20), null);
            assertEquals(30, result);
        }
        
        @Test
        @DisplayName("should use default value for optional parameter")
        void testOptionalParamWithDefault() {
            Object result = paramHandler.handleRpc("greet", Map.of("name", "Smith"), null);
            assertEquals("Hello, Mr. Smith!", result);
        }
        
        @Test
        @DisplayName("should override default value when provided")
        void testOptionalParamOverride() {
            Object result = paramHandler.handleRpc("greet", 
                Map.of("name", "Smith", "title", "Dr."), null);
            assertEquals("Hello, Dr. Smith!", result);
        }
        
        @Test
        @DisplayName("should pass context to @Param annotated method")
        @SuppressWarnings("unchecked")
        void testParamWithContext() {
            Context ctx = paramHandler.createContext("did:wba:test:caller", null, null);
            Object result = paramHandler.handleRpc("calculate", 
                Map.of("x", 3.0, "y", 4.0), ctx);
            
            assertTrue(result instanceof Map);
            Map<String, Object> map = (Map<String, Object>) result;
            assertEquals(7.0, map.get("sum"));
            assertEquals(12.0, map.get("product"));
            assertEquals("did:wba:test:caller", map.get("caller"));
        }
        
        @Test
        @DisplayName("should throw error for missing required parameter")
        void testMissingRequiredParam() {
            assertThrows(JsonRpc.RpcException.class, () -> {
                paramHandler.handleRpc("greet", Map.of(), null);
            });
        }
    }
    
    @Nested
    @DisplayName("Async Method Tests")
    class AsyncMethodTests {
        
        @AnpAgent(name = "Async Test", did = "did:wba:example.com:async-test")
        public static class AsyncTestAgent {
            
            @Interface(name = "asyncAdd", description = "Add asynchronously")
            public CompletableFuture<Integer> asyncAdd(
                @Param("a") int a,
                @Param("b") int b
            ) {
                return CompletableFuture.supplyAsync(() -> a + b);
            }
        }
        
        @Test
        @DisplayName("should handle async method with CompletableFuture")
        void testAsyncMethod() {
            AgentHandler asyncHandler = new AgentHandler(new AsyncTestAgent());
            Object result = asyncHandler.handleRpc("asyncAdd", Map.of("a", 5, "b", 7), null);
            assertEquals(12, result);
        }
        
        @Test
        @DisplayName("should support handleRpcAsync")
        void testHandleRpcAsync() throws Exception {
            AgentHandler asyncHandler = new AgentHandler(new AsyncTestAgent());
            CompletableFuture<Object> future = asyncHandler.handleRpcAsync(
                "asyncAdd", Map.of("a", 10, "b", 20), null);
            
            Object result = future.get();
            assertEquals(30, result);
        }
    }
}
