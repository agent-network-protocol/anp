/**
 * @program: anp4java
 * @author: Ruitao.Zhai
 * @date: 2025-01-29
 */
package com.agentconnect.authentication;

import com.agentconnect.utils.CryptoTool;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.interfaces.ECPrivateKey;
import java.util.HashMap;
import java.util.Map;

/**
 * Simplified DID authentication client providing HTTP authentication headers.
 */
public class DIDWbaAuthHeader {
    private static final Logger logger = LoggerFactory.getLogger(DIDWbaAuthHeader.class);
    private static final ObjectMapper objectMapper = new ObjectMapper().enable(com.fasterxml.jackson.core.JsonParser.Feature.STRICT_DUPLICATE_DETECTION).enable(com.fasterxml.jackson.databind.DeserializationFeature.FAIL_ON_TRAILING_TOKENS);
    
    private final String didDocumentPath;
    private final String privateKeyPath;
    
    // State variables
    private Map<String, Object> didDocument;
    private final Map<String, String> tokens = new HashMap<>();
    
    /**
     * Initialize the DID authentication client.
     *
     * @param didDocumentPath Path to the DID document (absolute or relative path)
     * @param privateKeyPath  Path to the private key (absolute or relative path)
     */
    public DIDWbaAuthHeader(String didDocumentPath, String privateKeyPath) {
        this.didDocumentPath = didDocumentPath;
        this.privateKeyPath = privateKeyPath;
        
        logger.info("DIDWbaAuthHeader initialized");
    }
    
    /**
     * Extract domain from URL.
     *
     * @param serverUrl Server URL
     * @return Domain
     */
    private String getDomain(String serverUrl) {
        try {
            java.net.URI uri=java.net.URI.create(serverUrl);
            PublicNetworkPolicy.origin(uri);
            return uri.getHost().toLowerCase(java.util.Locale.ROOT);
        } catch (Exception e) {
            logger.error("Error parsing URL: {}", e.getMessage(), e);
            throw new RuntimeException("Failed to parse URL", e);
        }
    }
    
    /**
     * Load DID document.
     *
     * @return DID document as Map
     */
    @SuppressWarnings("unchecked")
    private Map<String, Object> loadDidDocument() {
        try {
            if (didDocument != null) {
                return didDocument;
            }
            
            File didFile = new File(didDocumentPath);
            
            didDocument = objectMapper.readValue(didFile, Map.class);
            
            logger.info("Loaded DID document: {}", didDocumentPath);
            return didDocument;
        } catch (Exception e) {
            logger.error("Error loading DID document: {}", e.getMessage(), e);
            throw new RuntimeException("Failed to load DID document", e);
        }
    }
    
    /**
     * Load private key.
     *
     * @return EC private key
     */
    private ECPrivateKey loadPrivateKey() {
        try {
            byte[] privateKeyData = Files.readAllBytes(Paths.get(privateKeyPath));
            String privateKeyPem = new String(privateKeyData);
            
            ECPrivateKey privateKey = CryptoTool.loadPrivateKeyFromPem(privateKeyPem);
            

            return privateKey;
        } catch (Exception e) {
            logger.error("Error loading private key: {}", e.getMessage(), e);
            throw new RuntimeException("Failed to load private key", e);
        }
    }
    
    /**
     * Sign callback function.
     *
     * @param content        Content to sign
     * @param methodFragment Method fragment
     * @return Signature
     */
    private byte[] signCallback(byte[] content, String methodFragment) {
        try {
            ECPrivateKey privateKey = loadPrivateKey();
            
            // Create signature
            java.security.Signature signature = java.security.Signature.getInstance("SHA256withECDSA", "BC");
            signature.initSign(privateKey);
            signature.update(content);
            byte[] signedData = signature.sign();
            
            logger.debug("Signed content with method fragment: {}", methodFragment);
            return signedData;
        } catch (Exception e) {
            logger.error("Error signing content: {}", e.getMessage(), e);
            throw new RuntimeException("Failed to sign content", e);
        }
    }
    
    /**
     * Generate DID authentication header.
     *
     * @param domain Domain to authenticate with
     * @return Authentication header
     */
    public synchronized String generateAuthHeader(String domain) {
        try {
            Map<String, Object> didDocument = loadDidDocument();
            
            // Use the DIDWBA.SignCallback interface for the callback
            DIDWBA.SignCallback callback = this::signCallback;
            
            String authHeader = DIDWBA.generateAuthHeader(didDocument, domain, callback);

            logger.debug("Generated fresh authentication for approved domain");
            return authHeader;
        } catch (Exception e) {
            logger.error("Error generating authentication header: {}", e.getMessage(), e);
            throw new RuntimeException("Failed to generate authentication header", e);
        }
    }
    
    /**
     * Get authentication header.
     *
     * @param serverUrl Server URL
     * @param forceNew  Whether to force generate a new DID authentication header
     * @return HTTP header dictionary
     */
    public synchronized Map<String, String> getAuthHeader(String serverUrl, boolean forceNew) {
        String domain=getDomain(serverUrl);
        String origin=PublicNetworkPolicy.origin(java.net.URI.create(serverUrl));
        if(!forceNew && tokens.containsKey(origin))return Map.of("Authorization","Bearer "+tokens.get(origin));
        // Legacy proof headers are one-shot, not a reusable session cache.
        return Map.of("Authorization",generateAuthHeader(domain));
    }
    
    /**
     * Get authentication header with default parameter.
     *
     * @param serverUrl Server URL
     * @return HTTP header dictionary
     */
    public synchronized Map<String, String> getAuthHeader(String serverUrl) {
        return getAuthHeader(serverUrl, false);
    }
    
    /**
     * Update token from response headers.
     *
     * @param serverUrl Server URL
     * @param headers   Response header dictionary
     * @return Updated token, or null if no valid token is found
     */
    public synchronized String updateToken(String serverUrl, Map<String, String> headers) {
        String origin=PublicNetworkPolicy.origin(java.net.URI.create(serverUrl));
        if(!origin.startsWith("https://"))return null;
        String info=header(headers,"Authentication-Info"), token=null;
        if(info!=null) {
            Map<String,String> fields=new HashMap<>();
            for(String part:info.split(",")) {
                int equals=part.indexOf('=');if(equals<1)continue;
                String name=part.substring(0,equals).trim().toLowerCase(java.util.Locale.ROOT);
                String value=part.substring(equals+1).trim();
                if(value.startsWith("\"")&&value.endsWith("\""))value=value.substring(1,value.length()-1);
                if(fields.putIfAbsent(name,value)!=null)return null;
            }
            if(!fields.getOrDefault("token_type","Bearer").equalsIgnoreCase("Bearer"))return null;
            token=fields.get("access_token");
        } else {
            String authorization=header(headers,"Authorization");
            if(authorization!=null&&authorization.regionMatches(true,0,"Bearer ",0,7))token=authorization.substring(7);
        }
        if(token==null||token.length()>16384||!token.matches("[A-Za-z0-9._~+/=-]+"))return null;
        tokens.put(origin,token);
        return token;
    }
    
    /**
     * Clear token for the specified domain.
     *
     * @param serverUrl Server URL
     */
    public synchronized void clearToken(String serverUrl) {
        tokens.remove(PublicNetworkPolicy.origin(java.net.URI.create(serverUrl)));
    }
    
    /**
     * Clear all tokens for all domains.
     */
    public synchronized void clearAllTokens() {
        tokens.clear();
        logger.info("Cleared all tokens for all domains");
    }
    private static String header(Map<String,String> values,String name) {
        String result=null;
        for(var entry:values.entrySet())if(entry.getKey().equalsIgnoreCase(name)) {
            if(result!=null)throw new IllegalArgumentException("Ambiguous authentication header");
            result=entry.getValue();
        }
        return result;
    }

}