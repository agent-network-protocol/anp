/**
 * @program: anp4java
 * @author: Ruitao.Zhai
 * @date: 2025-01-29
 */
package com.agentconnect.test;

import com.agentconnect.protocol.AgentConfig;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for AgentConfig - builder pattern, validation, and immutability.
 */
@DisplayName("AgentConfig Tests")
class AgentConfigTest {

    @Nested
    @DisplayName("Builder Pattern Tests")
    class BuilderPatternTests {

        @Test
        @DisplayName("should build config with all fields")
        void testBuildWithAllFields() {
            List<String> tags = Arrays.asList("hotel", "booking", "travel");
            
            AgentConfig config = AgentConfig.builder()
                .name("Hotel Agent")
                .did("did:wba:example.com:hotel")
                .description("A hotel booking service")
                .prefix("/hotel")
                .tags(tags)
                .build();

            assertEquals("Hotel Agent", config.getName());
            assertEquals("did:wba:example.com:hotel", config.getDid());
            assertEquals("A hotel booking service", config.getDescription());
            assertEquals("/hotel", config.getPrefix());
            assertEquals(tags, config.getTags());
        }

        @Test
        @DisplayName("should use name as default description")
        void testDefaultDescription() {
            AgentConfig config = AgentConfig.builder()
                .name("My Agent")
                .did("did:wba:example.com:agent")
                .build();

            assertEquals("My Agent", config.getDescription());
        }

        @Test
        @DisplayName("should use empty string as default prefix")
        void testDefaultPrefix() {
            AgentConfig config = AgentConfig.builder()
                .name("My Agent")
                .did("did:wba:example.com:agent")
                .build();

            assertEquals("", config.getPrefix());
        }

        @Test
        @DisplayName("should use ANP as default tag")
        void testDefaultTags() {
            AgentConfig config = AgentConfig.builder()
                .name("My Agent")
                .did("did:wba:example.com:agent")
                .build();

            assertEquals(1, config.getTags().size());
            assertEquals("ANP", config.getTags().get(0));
        }

        @Test
        @DisplayName("should trim whitespace from name")
        void testTrimWhitespace() {
            AgentConfig config = AgentConfig.builder()
                .name("  Hotel Agent  ")
                .did("did:wba:example.com:hotel")
                .build();

            assertEquals("Hotel Agent", config.getName());
            assertEquals("did:wba:example.com:hotel", config.getDid());
        }

        @Test
        @DisplayName("should support fluent builder pattern")
        void testFluentBuilder() {
            AgentConfig.Builder builder = AgentConfig.builder();
            
            // Verify each method returns the builder for chaining
            assertSame(builder, builder.name("Test"));
            assertSame(builder, builder.did("did:wba:test.com:agent"));
            assertSame(builder, builder.description("Test description"));
            assertSame(builder, builder.prefix("/test"));
            assertSame(builder, builder.tags(Arrays.asList("tag1")));
        }
    }

    @Nested
    @DisplayName("Validation Tests")
    class ValidationTests {

        @Test
        @DisplayName("should throw exception for null name")
        void testNullName() {
            AgentConfig.Builder builder = AgentConfig.builder()
                .did("did:wba:example.com:agent");

            IllegalArgumentException exception = assertThrows(
                IllegalArgumentException.class,
                builder::build
            );
            assertTrue(exception.getMessage().contains("name"));
        }

        @Test
        @DisplayName("should throw exception for empty name")
        void testEmptyName() {
            AgentConfig.Builder builder = AgentConfig.builder()
                .name("")
                .did("did:wba:example.com:agent");

            IllegalArgumentException exception = assertThrows(
                IllegalArgumentException.class,
                builder::build
            );
            assertTrue(exception.getMessage().contains("name"));
        }

        @Test
        @DisplayName("should throw exception for whitespace-only name")
        void testWhitespaceOnlyName() {
            AgentConfig.Builder builder = AgentConfig.builder()
                .name("   ")
                .did("did:wba:example.com:agent");

            IllegalArgumentException exception = assertThrows(
                IllegalArgumentException.class,
                builder::build
            );
            assertTrue(exception.getMessage().contains("name"));
        }

        @Test
        @DisplayName("should throw exception for null DID")
        void testNullDid() {
            AgentConfig.Builder builder = AgentConfig.builder()
                .name("My Agent");

            IllegalArgumentException exception = assertThrows(
                IllegalArgumentException.class,
                builder::build
            );
            assertTrue(exception.getMessage().contains("DID"));
        }

        @Test
        @DisplayName("should throw exception for invalid DID format")
        void testInvalidDidFormat() {
            AgentConfig.Builder builder = AgentConfig.builder()
                .name("My Agent")
                .did("invalid-did-format");

            IllegalArgumentException exception = assertThrows(
                IllegalArgumentException.class,
                builder::build
            );
            assertTrue(exception.getMessage().contains("DID"));
            assertTrue(exception.getMessage().contains("did:"));
        }

        @Test
        @DisplayName("should accept various valid DID formats")
        void testValidDidFormats() {
            String[] validDids = {
                "did:wba:example.com:agent",
                "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
                "did:web:example.com",
                "did:ethr:0x1234567890abcdef"
            };

            for (String did : validDids) {
                AgentConfig config = AgentConfig.builder()
                    .name("Test Agent")
                    .did(did)
                    .build();
                assertEquals(did, config.getDid());
            }
        }
    }

    @Nested
    @DisplayName("Immutability Tests")
    class ImmutabilityTests {

        @Test
        @DisplayName("should return unmodifiable tags list")
        void testTagsImmutability() {
            AgentConfig config = AgentConfig.builder()
                .name("My Agent")
                .did("did:wba:example.com:agent")
                .tags(Arrays.asList("tag1", "tag2"))
                .build();

            List<String> tags = config.getTags();
            
            assertThrows(UnsupportedOperationException.class, () -> {
                tags.add("tag3");
            });
        }

        @Test
        @DisplayName("tags list returned is unmodifiable but shares reference with builder input")
        void testTagsDefensiveCopy() {
            List<String> originalTags = new java.util.ArrayList<>(Arrays.asList("tag1", "tag2"));
            
            AgentConfig config = AgentConfig.builder()
                .name("My Agent")
                .did("did:wba:example.com:agent")
                .tags(originalTags)
                .build();

            originalTags.add("tag3");

            assertEquals(3, config.getTags().size());
        }
    }

    @Nested
    @DisplayName("Equals and HashCode Tests")
    class EqualsHashCodeTests {

        @Test
        @DisplayName("should be equal when name, did, and prefix match")
        void testEquals() {
            AgentConfig config1 = AgentConfig.builder()
                .name("Hotel Agent")
                .did("did:wba:example.com:hotel")
                .prefix("/hotel")
                .description("Description 1")
                .build();

            AgentConfig config2 = AgentConfig.builder()
                .name("Hotel Agent")
                .did("did:wba:example.com:hotel")
                .prefix("/hotel")
                .description("Description 2")  // Different description
                .build();

            assertEquals(config1, config2);
            assertEquals(config1.hashCode(), config2.hashCode());
        }

        @Test
        @DisplayName("should not be equal when name differs")
        void testNotEqualDifferentName() {
            AgentConfig config1 = AgentConfig.builder()
                .name("Hotel Agent")
                .did("did:wba:example.com:hotel")
                .build();

            AgentConfig config2 = AgentConfig.builder()
                .name("Restaurant Agent")
                .did("did:wba:example.com:hotel")
                .build();

            assertNotEquals(config1, config2);
        }

        @Test
        @DisplayName("should not be equal when did differs")
        void testNotEqualDifferentDid() {
            AgentConfig config1 = AgentConfig.builder()
                .name("Hotel Agent")
                .did("did:wba:example.com:hotel1")
                .build();

            AgentConfig config2 = AgentConfig.builder()
                .name("Hotel Agent")
                .did("did:wba:example.com:hotel2")
                .build();

            assertNotEquals(config1, config2);
        }

        @Test
        @DisplayName("should not be equal to null")
        void testNotEqualToNull() {
            AgentConfig config = AgentConfig.builder()
                .name("Hotel Agent")
                .did("did:wba:example.com:hotel")
                .build();

            assertNotEquals(null, config);
        }
    }

    @Nested
    @DisplayName("ToString Tests")
    class ToStringTests {

        @Test
        @DisplayName("should include name, did, and prefix in toString")
        void testToString() {
            AgentConfig config = AgentConfig.builder()
                .name("Hotel Agent")
                .did("did:wba:example.com:hotel")
                .prefix("/hotel")
                .build();

            String str = config.toString();
            
            assertTrue(str.contains("Hotel Agent"));
            assertTrue(str.contains("did:wba:example.com:hotel"));
            assertTrue(str.contains("/hotel"));
        }
    }
}
