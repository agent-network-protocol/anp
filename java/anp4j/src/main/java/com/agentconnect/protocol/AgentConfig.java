/**
 * @program: anp4java
 * @author: Ruitao.Zhai
 * @date: 2025-01-29
 */
package com.agentconnect.protocol;

import java.util.Collections;
import java.util.List;
import java.util.Objects;

/**
 * Immutable agent configuration.
 * 
 * All fields are read-only to ensure configuration is not accidentally modified.
 * This is important for concurrent access and debugging.
 * 
 * Example:
 *     AgentConfig config = new AgentConfig.Builder()
 *         .name("Hotel Agent")
 *         .did("did:wba:example.com:hotel")
 *         .description("Hotel booking service")
 *         .prefix("/hotel")
 *         .build();
 */
public final class AgentConfig {
    
    private final String name;
    private final String did;
    private final String description;
    private final String prefix;
    private final String baseUrl;
    private final String version;
    private final List<String> tags;
    
    private AgentConfig(Builder builder) {
        if (builder.name == null || builder.name.trim().isEmpty()) {
            throw new IllegalArgumentException("Agent name cannot be empty");
        }
        if (builder.did == null || !builder.did.startsWith("did:")) {
            throw new IllegalArgumentException(
                "Invalid DID format: " + builder.did + ". DID must start with 'did:'"
            );
        }
        
        this.name = builder.name.trim();
        this.did = builder.did.trim();
        this.description = builder.description != null ? builder.description : this.name;
        this.prefix = builder.prefix != null ? builder.prefix : "";
        this.baseUrl = builder.baseUrl != null ? builder.baseUrl : "";
        this.version = builder.version != null ? builder.version : "1.0.0";
        this.tags = builder.tags != null 
            ? Collections.unmodifiableList(builder.tags) 
            : Collections.singletonList("ANP");
    }
    
    public String getName() {
        return name;
    }
    
    public String getDid() {
        return did;
    }
    
    public String getDescription() {
        return description;
    }
    
    public String getPrefix() {
        return prefix;
    }
    
    public String getBaseUrl() {
        return baseUrl;
    }
    
    public String getVersion() {
        return version;
    }
    
    public List<String> getTags() {
        return tags;
    }
    
    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        AgentConfig that = (AgentConfig) o;
        return Objects.equals(name, that.name) &&
               Objects.equals(did, that.did) &&
               Objects.equals(prefix, that.prefix);
    }
    
    @Override
    public int hashCode() {
        return Objects.hash(name, did, prefix);
    }
    
    @Override
    public String toString() {
        return "AgentConfig{" +
               "name='" + name + '\'' +
               ", did='" + did + '\'' +
               ", prefix='" + prefix + '\'' +
               '}';
    }
    
    /**
     * Builder for AgentConfig.
     */
    public static class Builder {
        private String name;
        private String did;
        private String description;
        private String prefix;
        private String baseUrl;
        private String version;
        private List<String> tags;
        
        public Builder name(String name) {
            this.name = name;
            return this;
        }
        
        public Builder did(String did) {
            this.did = did;
            return this;
        }
        
        public Builder description(String description) {
            this.description = description;
            return this;
        }
        
        public Builder prefix(String prefix) {
            this.prefix = prefix;
            return this;
        }
        
        public Builder baseUrl(String baseUrl) {
            this.baseUrl = baseUrl;
            return this;
        }
        
        public Builder version(String version) {
            this.version = version;
            return this;
        }
        
        public Builder tags(List<String> tags) {
            this.tags = tags;
            return this;
        }
        
        public AgentConfig build() {
            return new AgentConfig(this);
        }
    }
    
    public static Builder builder() {
        return new Builder();
    }
}
