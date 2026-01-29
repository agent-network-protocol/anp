/**
 * @program: anp4java
 * @author: Ruitao.Zhai
 * @date: 2025-01-29
 */
package com.agentconnect.test;

import com.agentconnect.protocol.AgentConfig;
import com.agentconnect.protocol.AgentDescription;
import com.agentconnect.protocol.RPCMethodInfo;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.util.*;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for AgentDescription - ad.json generation.
 */
@DisplayName("AgentDescription Tests")
class AgentDescriptionTest {

    private AgentConfig config;
    private List<RPCMethodInfo> methods;
    private static final String BASE_URL = "http://localhost:8080";

    @BeforeEach
    void setUp() {
        config = AgentConfig.builder()
            .name("Hotel Agent")
            .did("did:wba:example.com:hotel")
            .description("A hotel booking service")
            .prefix("/hotel")
            .tags(Arrays.asList("hotel", "booking"))
            .build();

        methods = new ArrayList<>();
        
        // Add a content mode method
        Map<String, Object> searchParams = new LinkedHashMap<>();
        searchParams.put("type", "object");
        searchParams.put("properties", Map.of(
            "query", Map.of("type", "string"),
            "limit", Map.of("type", "integer")
        ));
        
        methods.add(RPCMethodInfo.builder()
            .name("search")
            .description("Search for hotels")
            .paramsSchema(searchParams)
            .resultSchema(Map.of("type", "object"))
            .mode(RPCMethodInfo.Mode.CONTENT)
            .build());
    }

    @Nested
    @DisplayName("Basic Generation Tests")
    class BasicGenerationTests {

        @Test
        @DisplayName("should generate ad.json with JSON-LD context")
        void testJsonLdContext() {
            Map<String, Object> ad = AgentDescription.generate(config, methods, null, BASE_URL);

            assertTrue(ad.containsKey("@context"));
            @SuppressWarnings("unchecked")
            Map<String, Object> context = (Map<String, Object>) ad.get("@context");
            
            assertEquals("https://agent-network-protocol.com/ad/", context.get("ad"));
            assertEquals("https://w3id.org/did/", context.get("did"));
            assertEquals("https://schema.org/", context.get("schema"));
        }

        @Test
        @DisplayName("should generate ad.json with correct type")
        void testType() {
            Map<String, Object> ad = AgentDescription.generate(config, methods, null, BASE_URL);

            assertEquals("ad:AgentDescription", ad.get("@type"));
        }

        @Test
        @DisplayName("should include agent name")
        void testName() {
            Map<String, Object> ad = AgentDescription.generate(config, methods, null, BASE_URL);

            assertEquals("Hotel Agent", ad.get("name"));
        }

        @Test
        @DisplayName("should include agent DID")
        void testDid() {
            Map<String, Object> ad = AgentDescription.generate(config, methods, null, BASE_URL);

            assertEquals("did:wba:example.com:hotel", ad.get("did"));
        }

        @Test
        @DisplayName("should include agent description")
        void testDescription() {
            Map<String, Object> ad = AgentDescription.generate(config, methods, null, BASE_URL);

            assertEquals("A hotel booking service", ad.get("description"));
        }
    }

    @Nested
    @DisplayName("Interface Generation Tests")
    class InterfaceGenerationTests {

        @Test
        @DisplayName("should generate interfaces section for content mode methods")
        void testContentModeInterface() {
            Map<String, Object> ad = AgentDescription.generate(config, methods, null, BASE_URL);

            assertTrue(ad.containsKey("interfaces"));
            @SuppressWarnings("unchecked")
            List<Map<String, Object>> interfaces = (List<Map<String, Object>>) ad.get("interfaces");
            
            assertFalse(interfaces.isEmpty());
            
            Map<String, Object> mainInterface = interfaces.get(0);
            assertEquals("StructuredInterface", mainInterface.get("type"));
            assertEquals("openrpc", mainInterface.get("protocol"));
            assertEquals("http://localhost:8080/hotel/interface.json", mainInterface.get("url"));
        }

        @Test
        @DisplayName("should generate separate interfaces for link mode methods")
        void testLinkModeInterface() {
            // Add a link mode method
            methods.add(RPCMethodInfo.builder()
                .name("book")
                .description("Book a hotel room")
                .mode(RPCMethodInfo.Mode.LINK)
                .build());

            Map<String, Object> ad = AgentDescription.generate(config, methods, null, BASE_URL);

            @SuppressWarnings("unchecked")
            List<Map<String, Object>> interfaces = (List<Map<String, Object>>) ad.get("interfaces");
            
            // Should have 2 interfaces: main interface.json + link mode method
            assertEquals(2, interfaces.size());
            
            // Check link mode interface
            Map<String, Object> linkInterface = interfaces.get(1);
            assertEquals("StructuredInterface", linkInterface.get("type"));
            assertEquals("openrpc", linkInterface.get("protocol"));
            assertEquals("http://localhost:8080/hotel/interface/book.json", linkInterface.get("url"));
            assertEquals("Book a hotel room", linkInterface.get("description"));
        }

        @Test
        @DisplayName("should not generate main interface when only link mode methods exist")
        void testOnlyLinkModeMethods() {
            List<RPCMethodInfo> linkOnlyMethods = new ArrayList<>();
            linkOnlyMethods.add(RPCMethodInfo.builder()
                .name("book")
                .description("Book a hotel room")
                .mode(RPCMethodInfo.Mode.LINK)
                .build());

            Map<String, Object> ad = AgentDescription.generate(config, linkOnlyMethods, null, BASE_URL);

            @SuppressWarnings("unchecked")
            List<Map<String, Object>> interfaces = (List<Map<String, Object>>) ad.get("interfaces");
            
            // Should only have link mode interface
            assertEquals(1, interfaces.size());
            assertTrue(interfaces.get(0).get("url").toString().contains("/interface/book.json"));
        }

        @Test
        @DisplayName("should not include interfaces section when no methods")
        void testNoMethods() {
            Map<String, Object> ad = AgentDescription.generate(config, new ArrayList<>(), null, BASE_URL);

            // interfaces should be empty or not present
            if (ad.containsKey("interfaces")) {
                @SuppressWarnings("unchecked")
                List<Map<String, Object>> interfaces = (List<Map<String, Object>>) ad.get("interfaces");
                assertTrue(interfaces.isEmpty());
            }
        }
    }

    @Nested
    @DisplayName("URL Generation Tests")
    class UrlGenerationTests {

        @Test
        @DisplayName("should use prefix in interface URLs")
        void testPrefixInUrls() {
            Map<String, Object> ad = AgentDescription.generate(config, methods, null, BASE_URL);

            @SuppressWarnings("unchecked")
            List<Map<String, Object>> interfaces = (List<Map<String, Object>>) ad.get("interfaces");
            
            String url = (String) interfaces.get(0).get("url");
            assertTrue(url.contains("/hotel/"));
        }

        @Test
        @DisplayName("should handle empty prefix")
        void testEmptyPrefix() {
            AgentConfig noPrefix = AgentConfig.builder()
                .name("Agent")
                .did("did:wba:example.com:agent")
                .prefix("")
                .build();

            Map<String, Object> ad = AgentDescription.generate(noPrefix, methods, null, BASE_URL);

            @SuppressWarnings("unchecked")
            List<Map<String, Object>> interfaces = (List<Map<String, Object>>) ad.get("interfaces");
            
            String url = (String) interfaces.get(0).get("url");
            assertEquals("http://localhost:8080/interface.json", url);
        }

        @Test
        @DisplayName("should handle different base URLs")
        void testDifferentBaseUrls() {
            String[] baseUrls = {
                "http://localhost:8080",
                "https://api.example.com",
                "http://192.168.1.1:3000"
            };

            for (String baseUrl : baseUrls) {
                Map<String, Object> ad = AgentDescription.generate(config, methods, null, baseUrl);

                @SuppressWarnings("unchecked")
                List<Map<String, Object>> interfaces = (List<Map<String, Object>>) ad.get("interfaces");
                
                String url = (String) interfaces.get(0).get("url");
                assertTrue(url.startsWith(baseUrl));
            }
        }
    }

    @Nested
    @DisplayName("JSON Serialization Tests")
    class JsonSerializationTests {

        @Test
        @DisplayName("should convert to JSON string")
        void testToJson() throws Exception {
            Map<String, Object> ad = AgentDescription.generate(config, methods, null, BASE_URL);
            
            String json = AgentDescription.toJson(ad);
            
            assertNotNull(json);
            assertTrue(json.contains("\"@context\""));
            assertTrue(json.contains("\"@type\""));
            assertTrue(json.contains("\"name\""));
            assertTrue(json.contains("\"did\""));
            assertTrue(json.contains("Hotel Agent"));
        }

        @Test
        @DisplayName("should produce pretty-printed JSON")
        void testPrettyPrint() throws Exception {
            Map<String, Object> ad = AgentDescription.generate(config, methods, null, BASE_URL);
            
            String json = AgentDescription.toJson(ad);
            
            // Pretty-printed JSON should have newlines
            assertTrue(json.contains("\n"));
        }
    }

    @Nested
    @DisplayName("Multiple Methods Tests")
    class MultipleMethodsTests {

        @Test
        @DisplayName("should handle multiple content mode methods")
        void testMultipleContentMethods() {
            methods.add(RPCMethodInfo.builder()
                .name("getDetails")
                .description("Get hotel details")
                .mode(RPCMethodInfo.Mode.CONTENT)
                .build());

            methods.add(RPCMethodInfo.builder()
                .name("checkAvailability")
                .description("Check room availability")
                .mode(RPCMethodInfo.Mode.CONTENT)
                .build());

            Map<String, Object> ad = AgentDescription.generate(config, methods, null, BASE_URL);

            @SuppressWarnings("unchecked")
            List<Map<String, Object>> interfaces = (List<Map<String, Object>>) ad.get("interfaces");
            
            // All content mode methods should be in single interface.json
            assertEquals(1, interfaces.size());
            assertEquals("http://localhost:8080/hotel/interface.json", interfaces.get(0).get("url"));
        }

        @Test
        @DisplayName("should handle mixed mode methods")
        void testMixedModeMethods() {
            // Add link mode methods
            methods.add(RPCMethodInfo.builder()
                .name("book")
                .description("Book a room")
                .mode(RPCMethodInfo.Mode.LINK)
                .build());

            methods.add(RPCMethodInfo.builder()
                .name("cancel")
                .description("Cancel booking")
                .mode(RPCMethodInfo.Mode.LINK)
                .build());

            Map<String, Object> ad = AgentDescription.generate(config, methods, null, BASE_URL);

            @SuppressWarnings("unchecked")
            List<Map<String, Object>> interfaces = (List<Map<String, Object>>) ad.get("interfaces");
            
            // 1 main interface + 2 link mode interfaces
            assertEquals(3, interfaces.size());
        }
    }
}
