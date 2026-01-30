/**
 * @program: anp4java
 * @author: Ruitao.Zhai
 * @date: 2025-01-29
 */
package com.agentconnect.protocol;

import java.lang.reflect.Method;
import java.util.Map;
import java.util.Objects;

/**
 * RPC method information.
 * 
 * Stores RPC method metadata, including name, description, and schemas for
 * parameters and return values. All fields are read-only to ensure metadata
 * consistency.
 */
public final class RPCMethodInfo {
    
    /**
     * Interface mode for ad.json
     */
    public enum Mode {
        /** Embeds OpenRPC document */
        CONTENT,
        /** Provides URL reference only */
        LINK
    }
    
    private final String name;
    private final String description;
    private final Map<String, Object> paramsSchema;
    private final Map<String, Object> resultSchema;
    private final Method handler;
    private final String protocol;
    private final Mode mode;
    private final boolean hasContext;
    
    private RPCMethodInfo(Builder builder) {
        this.name = Objects.requireNonNull(builder.name, "name cannot be null").trim();
        this.description = builder.description != null ? builder.description.trim() : "";
        this.paramsSchema = builder.paramsSchema;
        this.resultSchema = builder.resultSchema;
        this.handler = builder.handler;
        this.protocol = builder.protocol;
        this.mode = builder.mode != null ? builder.mode : Mode.CONTENT;
        this.hasContext = builder.hasContext;
    }
    
    public String getName() {
        return name;
    }
    
    public String getDescription() {
        return description;
    }
    
    public Map<String, Object> getParamsSchema() {
        return paramsSchema;
    }
    
    public Map<String, Object> getResultSchema() {
        return resultSchema;
    }
    
    public Method getHandler() {
        return handler;
    }
    
    public String getProtocol() {
        return protocol;
    }
    
    public Mode getMode() {
        return mode;
    }
    
    public boolean hasContext() {
        return hasContext;
    }
    
    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        RPCMethodInfo that = (RPCMethodInfo) o;
        return Objects.equals(name, that.name);
    }
    
    @Override
    public int hashCode() {
        return Objects.hash(name);
    }
    
    @Override
    public String toString() {
        return "RPCMethodInfo{" +
               "name='" + name + '\'' +
               ", description='" + description + '\'' +
               ", mode=" + mode +
               ", protocol='" + protocol + '\'' +
               '}';
    }
    
    public static class Builder {
        private String name;
        private String description;
        private Map<String, Object> paramsSchema;
        private Map<String, Object> resultSchema;
        private Method handler;
        private String protocol;
        private Mode mode;
        private boolean hasContext;
        
        public Builder name(String name) {
            this.name = name;
            return this;
        }
        
        public Builder description(String description) {
            this.description = description;
            return this;
        }
        
        public Builder paramsSchema(Map<String, Object> paramsSchema) {
            this.paramsSchema = paramsSchema;
            return this;
        }
        
        public Builder resultSchema(Map<String, Object> resultSchema) {
            this.resultSchema = resultSchema;
            return this;
        }
        
        public Builder handler(Method handler) {
            this.handler = handler;
            return this;
        }
        
        public Builder protocol(String protocol) {
            this.protocol = protocol;
            return this;
        }
        
        public Builder mode(Mode mode) {
            this.mode = mode;
            return this;
        }
        
        public Builder hasContext(boolean hasContext) {
            this.hasContext = hasContext;
            return this;
        }
        
        public RPCMethodInfo build() {
            return new RPCMethodInfo(this);
        }
    }
    
    public static Builder builder() {
        return new Builder();
    }
}
