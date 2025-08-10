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
    private static final ObjectMapper objectMapper = new ObjectMapper();
    
    private final String didDocumentPath;
    private final String privateKeyPath;
    
    // State variables
    private Map<String, Object> didDocument;
    private final Map<String, String> authHeaders = new HashMap<>();
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
            URL url = new URL(serverUrl);
            return url.getHost();
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
            
            logger.debug("Loaded private key: {}", privateKeyPath);
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
    public String generateAuthHeader(String domain) {
        try {
            Map<String, Object> didDocument = loadDidDocument();
            
            // Use the DIDWBA.SignCallback interface for the callback
            DIDWBA.SignCallback callback = this::signCallback;
            
            String authHeader = DIDWBA.generateAuthHeader(didDocument, domain, callback);

            logger.info("Generated authentication header for domain {}: {}...", domain, 
                    authHeader.substring(0, Math.min(30, authHeader.length())));
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
    public Map<String, String> getAuthHeader(String serverUrl, boolean forceNew) {
        String domain = getDomain(serverUrl);
        
        // If there is a token and not forcing a new authentication header, return the token
        if (tokens.containsKey(domain) && !forceNew) {
            String token = tokens.get(domain);
            logger.info("Using existing token for domain {}", domain);
            Map<String, String> headers = new HashMap<>();
            headers.put("Authorization", "Bearer " + token);
            return headers;
        }
        
        // Otherwise, generate or use existing DID authentication header
        if (!authHeaders.containsKey(domain) || forceNew) {
            authHeaders.put(domain, generateAuthHeader(domain));
        }
        
        logger.info("Using DID authentication header for domain {}", domain);
        Map<String, String> headers = new HashMap<>();
        headers.put("Authorization", authHeaders.get(domain));
        return headers;
    }
    
    /**
     * Get authentication header with default parameter.
     *
     * @param serverUrl Server URL
     * @return HTTP header dictionary
     */
    public Map<String, String> getAuthHeader(String serverUrl) {
        return getAuthHeader(serverUrl, false);
    }
    
    /**
     * Update token from response headers.
     *
     * @param serverUrl Server URL
     * @param headers   Response header dictionary
     * @return Updated token, or null if no valid token is found
     */
    public String updateToken(String serverUrl, Map<String, String> headers) {
        String domain = getDomain(serverUrl);
        String authHeader = headers.get("authorization");
        
        if (authHeader != null && authHeader.toLowerCase().startsWith("bearer ")) {
            String token = authHeader.substring(7); // Remove "Bearer " prefix
            tokens.put(domain, token);
            logger.info("Updated token for domain {}: {}...", domain,
                    token.substring(0, Math.min(30, token.length())));
            return token;
        } else {
            logger.debug("No valid token found in response headers for domain {}", domain);
            return null;
        }
    }
    
    /**
     * Clear token for the specified domain.
     *
     * @param serverUrl Server URL
     */
    public void clearToken(String serverUrl) {
        String domain = getDomain(serverUrl);
        if (tokens.containsKey(domain)) {
            tokens.remove(domain);
            logger.info("Cleared token for domain {}", domain);
        } else {
            logger.debug("No stored token for domain {}", domain);
        }
    }
    
    /**
     * Clear all tokens for all domains.
     */
    public void clearAllTokens() {
        tokens.clear();
        logger.info("Cleared all tokens for all domains");
    }
}