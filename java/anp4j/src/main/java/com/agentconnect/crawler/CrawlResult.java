/**
 * @program: anp4java
 * @author: Ruitao.Zhai
 * @date: 2025-01-29
 */
package com.agentconnect.crawler;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Immutable result container for ANP crawler operations.
 * 
 * Contains the fetched content, discovered tools in OpenAI format,
 * agent description metadata, and method definitions.
 * 
 * Example:
 *     CrawlResult result = CrawlResult.builder()
 *         .content("{\"name\": \"Hotel Agent\"}")
 *         .agentDescription(Map.of("name", "Hotel Agent"))
 *         .addTool(Map.of("type", "function", "function", Map.of("name", "search")))
 *         .addMethod(methodInfo)
 *         .build();
 *     
 *     // Access data
 *     String content = result.getContent();
 *     List<Map<String, Object>> tools = result.getTools();
 */
public final class CrawlResult {
    
    private final String content;
    private final List<Map<String, Object>> tools;
    private final Map<String, Object> agentDescription;
    private final List<MethodInfo> methods;
    private final String agentDescriptionUri;
    private final String contentUri;
    
    private CrawlResult(Builder builder) {
        this.content = builder.content;
        this.tools = Collections.unmodifiableList(new ArrayList<>(builder.tools));
        this.agentDescription = builder.agentDescription != null 
            ? Collections.unmodifiableMap(new LinkedHashMap<>(builder.agentDescription))
            : Collections.emptyMap();
        this.methods = Collections.unmodifiableList(new ArrayList<>(builder.methods));
        this.agentDescriptionUri = builder.agentDescriptionUri;
        this.contentUri = builder.contentUri;
    }
    
    /**
     * Get the raw content fetched from the URL.
     */
    public String getContent() {
        return content;
    }
    
    /**
     * Get the list of tools in OpenAI Tools format.
     * 
     * Each tool is a Map with structure:
     * {
     *     "type": "function",
     *     "function": {
     *         "name": "method_name",
     *         "description": "Method description",
     *         "parameters": {
     *             "type": "object",
     *             "properties": {...},
     *             "required": [...]
     *         }
     *     }
     * }
     */
    public List<Map<String, Object>> getTools() {
        return tools;
    }
    
    /**
     * Get the agent description metadata.
     */
    public Map<String, Object> getAgentDescription() {
        return agentDescription;
    }
    
    /**
     * Get the list of method definitions.
     */
    public List<MethodInfo> getMethods() {
        return methods;
    }
    
    /**
     * Get the agent description URI (first URL fetched).
     */
    public String getAgentDescriptionUri() {
        return agentDescriptionUri;
    }
    
    /**
     * Get the content URI (URL without query parameters).
     */
    public String getContentUri() {
        return contentUri;
    }
    
    /**
     * Check if any tools were discovered.
     */
    public boolean hasTools() {
        return !tools.isEmpty();
    }
    
    /**
     * Get the number of discovered tools.
     */
    public int getToolCount() {
        return tools.size();
    }
    
    /**
     * Get tool names.
     */
    public List<String> getToolNames() {
        List<String> names = new ArrayList<>();
        for (Map<String, Object> tool : tools) {
            @SuppressWarnings("unchecked")
            Map<String, Object> function = (Map<String, Object>) tool.get("function");
            if (function != null) {
                String name = (String) function.get("name");
                if (name != null) {
                    names.add(name);
                }
            }
        }
        return names;
    }
    
    /**
     * Create a new builder.
     */
    public static Builder builder() {
        return new Builder();
    }
    
    /**
     * Create an empty result.
     */
    public static CrawlResult empty() {
        return builder().build();
    }
    
    /**
     * Create an error result with content containing the error message.
     */
    public static CrawlResult error(String errorMessage, String agentDescriptionUri, String contentUri) {
        return builder()
            .content("Error: " + errorMessage)
            .agentDescriptionUri(agentDescriptionUri)
            .contentUri(contentUri)
            .build();
    }
    
    @Override
    public String toString() {
        return "CrawlResult{" +
            "contentUri='" + contentUri + '\'' +
            ", toolCount=" + tools.size() +
            ", methodCount=" + methods.size() +
            '}';
    }
    
    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        CrawlResult that = (CrawlResult) o;
        return Objects.equals(content, that.content) &&
            Objects.equals(tools, that.tools) &&
            Objects.equals(agentDescription, that.agentDescription) &&
            Objects.equals(methods, that.methods) &&
            Objects.equals(agentDescriptionUri, that.agentDescriptionUri) &&
            Objects.equals(contentUri, that.contentUri);
    }
    
    @Override
    public int hashCode() {
        return Objects.hash(content, tools, agentDescription, methods, agentDescriptionUri, contentUri);
    }
    
    /**
     * Builder for CrawlResult.
     */
    public static final class Builder {
        private String content;
        private List<Map<String, Object>> tools = new ArrayList<>();
        private Map<String, Object> agentDescription;
        private List<MethodInfo> methods = new ArrayList<>();
        private String agentDescriptionUri;
        private String contentUri;
        
        private Builder() {}
        
        public Builder content(String content) {
            this.content = content;
            return this;
        }
        
        public Builder tools(List<Map<String, Object>> tools) {
            this.tools = tools != null ? new ArrayList<>(tools) : new ArrayList<>();
            return this;
        }
        
        public Builder addTool(Map<String, Object> tool) {
            if (tool != null) {
                this.tools.add(tool);
            }
            return this;
        }
        
        public Builder agentDescription(Map<String, Object> agentDescription) {
            this.agentDescription = agentDescription;
            return this;
        }
        
        public Builder methods(List<MethodInfo> methods) {
            this.methods = methods != null ? new ArrayList<>(methods) : new ArrayList<>();
            return this;
        }
        
        public Builder addMethod(MethodInfo method) {
            if (method != null) {
                this.methods.add(method);
            }
            return this;
        }
        
        public Builder agentDescriptionUri(String agentDescriptionUri) {
            this.agentDescriptionUri = agentDescriptionUri;
            return this;
        }
        
        public Builder contentUri(String contentUri) {
            this.contentUri = contentUri;
            return this;
        }
        
        public CrawlResult build() {
            return new CrawlResult(this);
        }
    }
    
    /**
     * Method information extracted from OpenRPC.
     */
    public static final class MethodInfo {
        private final String name;
        private final String description;
        private final String rpcUrl;
        private final Map<String, Object> schema;
        
        public MethodInfo(String name, String description, String rpcUrl, Map<String, Object> schema) {
            this.name = Objects.requireNonNull(name, "name cannot be null");
            this.description = description != null ? description : "";
            this.rpcUrl = Objects.requireNonNull(rpcUrl, "rpcUrl cannot be null");
            this.schema = schema != null 
                ? Collections.unmodifiableMap(new LinkedHashMap<>(schema))
                : Collections.emptyMap();
        }
        
        public String getName() {
            return name;
        }
        
        public String getDescription() {
            return description;
        }
        
        public String getRpcUrl() {
            return rpcUrl;
        }
        
        public Map<String, Object> getSchema() {
            return schema;
        }
        
        @Override
        public String toString() {
            return "MethodInfo{name='" + name + "', rpcUrl='" + rpcUrl + "'}";
        }
        
        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            MethodInfo that = (MethodInfo) o;
            return Objects.equals(name, that.name) &&
                Objects.equals(description, that.description) &&
                Objects.equals(rpcUrl, that.rpcUrl) &&
                Objects.equals(schema, that.schema);
        }
        
        @Override
        public int hashCode() {
            return Objects.hash(name, description, rpcUrl, schema);
        }
    }
}
