/**
 * @program: anp4java
 * @description: ANP SDK 配置属性
 * @author: Ruitao.Zhai
 * @date: 2025-01-21
 **/
package com.agentconnect.spring;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.ArrayList;
import java.util.List;

/**
 * ANP SDK 配置属性
 * 
 * 在 application.yml 中配置：
 * 
 * anp:
 *   enabled: true
 *   name: "My Agent"
 *   did: "did:wba:example.com:agent"
 *   description: "Agent description"
 *   prefix: "/agent"
 *   base-url: "http://localhost:8080"
 *   auth:
 *     enabled: true
 *     did-document-path: "/path/to/did.json"
 *     private-key-path: "/path/to/key.pem"
 *     exempt-paths:
 *       - "/agent/ad.json"
 *       - "/health"
 */
@ConfigurationProperties(prefix = "anp")
public class AnpProperties {
    
    private boolean enabled = true;
    private String name;
    private String did;
    private String description;
    private String prefix = "";
    private String baseUrl;
    private String version = "1.0.0";
    private List<String> tags = new ArrayList<>();
    private AuthProperties auth = new AuthProperties();
    
    public boolean isEnabled() {
        return enabled;
    }
    
    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }
    
    public String getName() {
        return name;
    }
    
    public void setName(String name) {
        this.name = name;
    }
    
    public String getDid() {
        return did;
    }
    
    public void setDid(String did) {
        this.did = did;
    }
    
    public String getDescription() {
        return description;
    }
    
    public void setDescription(String description) {
        this.description = description;
    }
    
    public String getPrefix() {
        return prefix;
    }
    
    public void setPrefix(String prefix) {
        this.prefix = prefix;
    }
    
    public String getBaseUrl() {
        return baseUrl;
    }
    
    public void setBaseUrl(String baseUrl) {
        this.baseUrl = baseUrl;
    }
    
    public String getVersion() {
        return version;
    }
    
    public void setVersion(String version) {
        this.version = version;
    }
    
    public List<String> getTags() {
        return tags;
    }
    
    public void setTags(List<String> tags) {
        this.tags = tags;
    }
    
    public AuthProperties getAuth() {
        return auth;
    }
    
    public void setAuth(AuthProperties auth) {
        this.auth = auth;
    }
    
    public static class AuthProperties {
        private boolean enabled = false;
        private String didDocumentPath;
        private String privateKeyPath;
        private List<String> exemptPaths = new ArrayList<>();
        private List<String> allowedDomains = new ArrayList<>();
        
        public boolean isEnabled() {
            return enabled;
        }
        
        public void setEnabled(boolean enabled) {
            this.enabled = enabled;
        }
        
        public String getDidDocumentPath() {
            return didDocumentPath;
        }
        
        public void setDidDocumentPath(String didDocumentPath) {
            this.didDocumentPath = didDocumentPath;
        }
        
        public String getPrivateKeyPath() {
            return privateKeyPath;
        }
        
        public void setPrivateKeyPath(String privateKeyPath) {
            this.privateKeyPath = privateKeyPath;
        }
        
        public List<String> getExemptPaths() {
            return exemptPaths;
        }
        
        public void setExemptPaths(List<String> exemptPaths) {
            this.exemptPaths = exemptPaths;
        }
        
        public List<String> getAllowedDomains() {
            return allowedDomains;
        }
        
        public void setAllowedDomains(List<String> allowedDomains) {
            this.allowedDomains = allowedDomains;
        }
    }
}
