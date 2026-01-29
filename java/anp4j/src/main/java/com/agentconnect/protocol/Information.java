/**
 * @program: anp4java
 * @author: Ruitao.Zhai
 * @date: 2025-01-29
 */
package com.agentconnect.protocol;

import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

/**
 * Information document definition.
 * 
 * Supports both URL mode (link to external resource) and Content mode (embedded content).
 * 
 * Example:
 *     // URL mode - hosted file
 *     Information info = Information.builder()
 *         .type("Product")
 *         .description("Room catalog")
 *         .path("/products/rooms.json")
 *         .build();
 *     
 *     // Content mode - embedded
 *     Information info = Information.builder()
 *         .type("Organization")
 *         .description("Contact info")
 *         .mode(InformationMode.CONTENT)
 *         .content(Map.of("name", "Hotel", "phone", "+1-234-567"))
 *         .build();
 */
public final class Information {
    
    public enum Mode {
        URL,
        CONTENT
    }
    
    private final String type;
    private final String description;
    private final Mode mode;
    private final String path;
    private final String url;
    private final String file;
    private final Map<String, Object> content;
    
    private Information(Builder builder) {
        this.type = Objects.requireNonNull(builder.type, "type cannot be null");
        this.description = Objects.requireNonNull(builder.description, "description cannot be null");
        this.mode = builder.mode != null ? builder.mode : Mode.URL;
        this.path = builder.path;
        this.url = builder.url;
        this.file = builder.file;
        this.content = builder.content;
        
        // Validation
        if (this.mode == Mode.URL && this.path == null && this.url == null) {
            throw new IllegalArgumentException("URL mode Information must have either 'path' or 'url'");
        }
        if (this.mode == Mode.CONTENT && this.content == null) {
            throw new IllegalArgumentException("Content mode Information must have 'content'");
        }
    }
    
    public String getType() {
        return type;
    }
    
    public String getDescription() {
        return description;
    }
    
    public Mode getMode() {
        return mode;
    }
    
    public String getPath() {
        return path;
    }
    
    public String getUrl() {
        return url;
    }
    
    public String getFile() {
        return file;
    }
    
    public Map<String, Object> getContent() {
        return content;
    }
    
    /**
     * Convert to dictionary for ad.json.
     * 
     * @param baseUrl Base URL for constructing full URLs
     * @return Map representation
     */
    public Map<String, Object> toMap(String baseUrl) {
        Map<String, Object> result = new HashMap<>();
        result.put("type", type);
        result.put("description", description);
        
        if (mode == Mode.CONTENT) {
            result.put("content", content);
        } else {
            if (url != null) {
                result.put("url", url);
            } else if (path != null) {
                if (baseUrl != null && !baseUrl.isEmpty()) {
                    String base = baseUrl.endsWith("/") ? baseUrl.substring(0, baseUrl.length() - 1) : baseUrl;
                    result.put("url", base + path);
                } else {
                    result.put("url", path);
                }
            }
        }
        
        return result;
    }
    
    public Map<String, Object> toMap() {
        return toMap("");
    }
    
    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Information that = (Information) o;
        return Objects.equals(type, that.type) &&
               Objects.equals(description, that.description) &&
               mode == that.mode;
    }
    
    @Override
    public int hashCode() {
        return Objects.hash(type, description, mode);
    }
    
    public static class Builder {
        private String type;
        private String description;
        private Mode mode;
        private String path;
        private String url;
        private String file;
        private Map<String, Object> content;
        
        public Builder type(String type) {
            this.type = type;
            return this;
        }
        
        public Builder description(String description) {
            this.description = description;
            return this;
        }
        
        public Builder mode(Mode mode) {
            this.mode = mode;
            return this;
        }
        
        public Builder path(String path) {
            this.path = path;
            return this;
        }
        
        public Builder url(String url) {
            this.url = url;
            return this;
        }
        
        public Builder file(String file) {
            this.file = file;
            return this;
        }
        
        public Builder content(Map<String, Object> content) {
            this.content = content;
            return this;
        }
        
        public Information build() {
            return new Information(this);
        }
    }
    
    public static Builder builder() {
        return new Builder();
    }
}
