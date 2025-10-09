package com.agentconnect.test.example;
import com.agentconnect.authentication.DIDWbaAuthHeader;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.file.Paths;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Map;
import java.util.concurrent.CompletableFuture;

public class DidWbaFullExample {
    
    private static final Logger logger = LoggerFactory.getLogger(DidWbaFullExample.class);
    
    private static final boolean IS_LOCAL_TESTING = false;
    
    // TODO: Change to your own server domain.
    // Or use the test domain we provide (currently using agent-network-protocol.com, 
    // will later change to service.agent-network-protocol.com)
    private static final String SERVER_DOMAIN = "service.agent-network-protocol.com";
    private static final String didKeysPath = "/Users/yanliqing/Documents/llm/ANP/anp-fork/AgentConnect/anp/java/src" +
            "/test/resources";
    public static void main(String[] args) {
        try {
            DidWbaFullExample example = new DidWbaFullExample();
            example.runFullExample().join(); // Wait for completion
        } catch (Exception e) {
            logger.error("Example execution failed", e);
            System.exit(1);
        } finally {
            // Clean up HTTP client
            HttpClientUtils.close();
        }
    }
    
    /**
     * Run the full DID WBA authentication example
     */
    public CompletableFuture<Void> runFullExample() {
        return CompletableFuture.runAsync(() -> {
            try {
                // 1. Generate unique identifier (8 bytes = 16 hex characters)
                String uniqueId = generateUniqueId();
                logger.info("Generated unique ID: {}", uniqueId);
                
                // 2. Set server information
                String serverDomain = SERVER_DOMAIN;
                String basePath = "/wba/user/" + uniqueId;
                String didPath = basePath + "/did.json";
                
                // 3. Create DID document
                logger.info("Creating DID document...");
                DidWbaDocumentCreator.DidDocumentResult result = DidWbaDocumentCreator.createDidWbaDocument(
                    serverDomain,
                    Arrays.asList("wba", "user", uniqueId),
                    "https://service.agent-network-protocol.com/agents/example/ad.json"
                );
                
                Map<String, Object> didDocument = result.getDidDocument();
                Map<String, byte[]> privateKeys = result.getPrivateKeys();
                
                // 4. Save private keys and DID document
                String userDir = FileUtils.savePrivateKeys(uniqueId, privateKeys, didDocument,didKeysPath);
                String didDocumentPath = Paths.get(userDir, "did.json").toString();
                String privateKeyPath = Paths.get(userDir, "key-1_private.pem").toString();
                
                logger.info("Saved files to directory: {}", userDir);
                
                // 5. Upload DID document (This should be stored on your server)
                String documentUrl = "https://" + serverDomain + didPath;
                logger.info("Uploading DID document to {}", documentUrl);
                
                String convertedUrl = HttpClientUtils.convertUrlForLocalTesting(documentUrl, IS_LOCAL_TESTING, SERVER_DOMAIN);
                logger.info("Converting URL from {} to {}", documentUrl, convertedUrl);
                
                Boolean uploadSuccess = HttpClientUtils.uploadJson(convertedUrl, didDocument).join();
                if (!uploadSuccess) {
                    logger.error("Failed to upload DID document");
                    return;
                }
                logger.info("DID document uploaded successfully");
                
                // 6. Verify uploaded document
                if (!verifyDidDocument(documentUrl, didDocument)) {
                    return;
                }
                
                // 7. Create DIDWbaAuthHeader instance
                logger.info("Creating DIDWbaAuthHeader instance...");
                DIDWbaAuthHeader authClient = new DIDWbaAuthHeader(didDocumentPath, privateKeyPath);
                
                // 8. Test DID authentication and get token
                String testUrl = "https://" + serverDomain + "/wba/test";
                logger.info("Testing DID authentication at {}", testUrl);
                
                AuthResult authResult = testDidAuth(testUrl, authClient);
                
                if (!authResult.success) {
                    logger.error("DID authentication test failed");
                    return;
                }
                
                logger.info("DID authentication test successful");
                
                if (authResult.token != null && !authResult.token.isEmpty()) {
                    logger.info("Received token from server");
                    logger.info("Verifying token...");
                    
                    // 9. Verify token
                    boolean tokenSuccess = verifyToken(testUrl, authClient);
                    if (tokenSuccess) {
                        logger.info("Token verification successful");
                    } else {
                        logger.error("Token verification failed");
                    }
                } else {
                    logger.info("No token received from server");
                }
                
                logger.info("DID WBA authentication example completed successfully!");
                
            } catch (Exception e) {
                logger.error("Example execution failed", e);
                throw new RuntimeException("Example execution failed", e);
            }
        });
    }
    
    /**
     * Generate unique identifier
     */
    private String generateUniqueId() {
        byte[] bytes = new byte[8];
        new SecureRandom().nextBytes(bytes);
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
    
    /**
     * Verify uploaded DID document matches the original one using canonical JSON format
     */
    private boolean verifyDidDocument(String documentUrl, Map<String, Object> originalDoc) {
        try {
            logger.info("Downloading DID document for verification...");
            
            String convertedUrl = HttpClientUtils.convertUrlForLocalTesting(documentUrl, IS_LOCAL_TESTING, SERVER_DOMAIN);
            logger.info("Converting URL from {} to {}", documentUrl, convertedUrl);
            
            Map<String, Object> downloadedDoc = HttpClientUtils.downloadJson(convertedUrl).join();
            if (downloadedDoc == null) {
                logger.error("Failed to download DID document");
                return false;
            }
            
            // Compare using canonical JSON
            String originalCanonical = JsonUtils.encodeCanonicalJson(originalDoc);
            String downloadedCanonical = JsonUtils.encodeCanonicalJson(downloadedDoc);
            
            if (downloadedCanonical.equals(originalCanonical)) {
                logger.info("Verification successful: uploaded and downloaded documents match");
                return true;
            } else {
                logger.error("Verification failed: documents do not match");
                logger.debug("Original canonical: {}", originalCanonical);
                logger.debug("Downloaded canonical: {}", downloadedCanonical);
                return false;
            }
            
        } catch (Exception e) {
            logger.error("Error during DID document verification", e);
            return false;
        }
    }
    
    /**
     * Test DID authentication and get token
     */
    private AuthResult testDidAuth(String url, DIDWbaAuthHeader authClient) {
        try {
            String convertedUrl = HttpClientUtils.convertUrlForLocalTesting(url, IS_LOCAL_TESTING, SERVER_DOMAIN);
            logger.info("Converting URL from {} to {}", url, convertedUrl);
            
            // Get authentication headers
            Map<String, String> authHeaders = authClient.getAuthHeader(convertedUrl);
            
            HttpClientUtils.HttpResult result = HttpClientUtils.sendGetWithHeaders(convertedUrl, authHeaders).join();
            
            // Update token
            String token = authClient.updateToken(convertedUrl, result.getHeaders());
            
            return new AuthResult(result.isSuccess(), token != null ? token : "");
            
        } catch (Exception e) {
            logger.error("DID authentication test failed", e);
            return new AuthResult(false, "");
        }
    }
    
    /**
     * Verify token with server
     */
    private boolean verifyToken(String url, DIDWbaAuthHeader authClient) {
        try {
            String convertedUrl = HttpClientUtils.convertUrlForLocalTesting(url, IS_LOCAL_TESTING, SERVER_DOMAIN);
            logger.info("Converting URL from {} to {}", url, convertedUrl);
            
            // Use stored token
            Map<String, String> authHeaders = authClient.getAuthHeader(convertedUrl);
            
            HttpClientUtils.HttpResult result = HttpClientUtils.sendGetWithHeaders(convertedUrl, authHeaders).join();
            
            return result.isSuccess();
            
        } catch (Exception e) {
            logger.error("Token verification failed", e);
            return false;
        }
    }
    
    /**
     * Container for authentication result
     */
    private static class AuthResult {
        private final boolean success;
        private final String token;
        
        public AuthResult(boolean success, String token) {
            this.success = success;
            this.token = token;
        }
    }
}