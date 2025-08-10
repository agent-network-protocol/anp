package com.agentconnect.authentication;

import com.agentconnect.utils.CryptoTool;
import com.agentconnect.utils.DIDGenerator;
import org.asynchttpclient.AsyncHttpClient;
import org.asynchttpclient.DefaultAsyncHttpClient;
import org.asynchttpclient.Response;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.interfaces.ECPrivateKey;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.CompletableFuture;

/**
 * Client for interacting with DID:ALL service.
 */
public class DIDAllClient {
    private static final Logger logger = LoggerFactory.getLogger(DIDAllClient.class);
    
    private final String didServiceUrl;
    private final String apiKey;
    
    /**
     * Constructor
     *
     * @param didServiceUrl URL of the DID service
     * @param apiKey API key for the DID service
     */
    public DIDAllClient(String didServiceUrl, String apiKey) {
        this.didServiceUrl = didServiceUrl;
        this.apiKey = apiKey;
    }
    
    /**
     * Generate DID document without registering to DID service
     *
     * @param communicationServiceEndpoint Communication service endpoint for DID document
     * @param routerDid Router's DID (optional, default is empty string)
     * @return Array containing [privateKeyPem, did, didDocumentJson]
     */
    public Object[] generateDidDocument(String communicationServiceEndpoint, String routerDid) {
        try {
            if (routerDid == null) {
                routerDid = "";
            }
            
            Object[] result = DIDGenerator.didGenerate(communicationServiceEndpoint, routerDid);
            
            ECPrivateKey privateKey = (ECPrivateKey) result[0];
            String did = (String) result[2];
            String didDocumentJson = (String) result[3];
            
            // Convert private key to PEM format
            String privateKeyPem = CryptoTool.getPemFromPrivateKey(privateKey);
            
            return new Object[] { privateKeyPem, did, didDocumentJson };
        } catch (Exception e) {
            logger.error("Failed to generate DID document: {}", e.getMessage(), e);
            throw new RuntimeException("Failed to generate DID document", e);
        }
    }
    
    /**
     * Generate DID document with a default empty router DID
     *
     * @param communicationServiceEndpoint Communication service endpoint for DID document
     * @return Array containing [privateKeyPem, did, didDocumentJson]
     */
    public Object[] generateDidDocument(String communicationServiceEndpoint) {
        return generateDidDocument(communicationServiceEndpoint, "");
    }
    
    /**
     * Register DID document to DID service asynchronously
     *
     * @param communicationServiceEndpoint Communication service endpoint for DID document
     * @param routerDid Router's DID (optional, default is empty string)
     * @return CompletableFuture that will complete with an array containing [privateKeyPem, did, didDocumentJson]
     */
    public CompletableFuture<Object[]> generateRegisterDidDocument(
            String communicationServiceEndpoint, String routerDid) {
        
        try {
            if (routerDid == null) {
                routerDid = "";
            }
            
            // Generate private key, public key, DID and DID document
            Object[] result = DIDGenerator.didGenerate(communicationServiceEndpoint, routerDid);
            
            ECPrivateKey privateKey = (ECPrivateKey) result[0];
            String did = (String) result[2];
            String didDocumentJson = (String) result[3];
            
            // Convert private key to PEM format
            String privateKeyPem = CryptoTool.getPemFromPrivateKey(privateKey);
            
            // Prepare request headers
            Map<String, String> headers = new HashMap<>();
            headers.put("Content-Type", "application/text");
            headers.put("Authorization", "Bearer " + apiKey);
            
            // Ensure correct request URL
            String requestUrl = didServiceUrl + "/v1/did";
            
            // Create HTTP client
            AsyncHttpClient client = new DefaultAsyncHttpClient();
            
            // Send asynchronous POST request
            return client.preparePost(requestUrl)
                .setHeader("Content-Type", "application/text")
                .setHeader("Authorization", "Bearer " + apiKey)
                .setBody(didDocumentJson)
                .execute()
                .toCompletableFuture()
                .thenApply(response -> {
                    try {
                        if (response.getStatusCode() == 200) {
                            return new Object[] { privateKeyPem, did, didDocumentJson };
                        } else {
                            logger.error("Failed to create DID document: {} {}", 
                                response.getStatusCode(), response.getResponseBody());
                            return null;
                        }
                    } finally {
                        try {
                            client.close();
                        } catch (Exception e) {
                            logger.warn("Failed to close HTTP client", e);
                        }
                    }
                });
        } catch (Exception e) {
            logger.error("Failed to register DID document: {}", e.getMessage(), e);
            return CompletableFuture.failedFuture(e);
        }
    }
    
    /**
     * Register DID document with a default empty router DID
     *
     * @param communicationServiceEndpoint Communication service endpoint for DID document
     * @return CompletableFuture that will complete with an array containing [privateKeyPem, did, didDocumentJson]
     */
    public CompletableFuture<Object[]> generateRegisterDidDocument(String communicationServiceEndpoint) {
        return generateRegisterDidDocument(communicationServiceEndpoint, "");
    }
    
    /**
     * Get DID document from DID service asynchronously
     *
     * @param did DID to resolve
     * @return CompletableFuture that will complete with the DID document as a string
     */
    public CompletableFuture<String> getDidDocument(String did) {
        try {
            // Prepare request headers
            Map<String, String> headers = new HashMap<>();
            headers.put("Accept", "application/text");
            headers.put("Authorization", "Bearer " + apiKey);
            
            // Construct complete request URL
            String requestUrl = didServiceUrl + "/v1/did/" + did;
            
            // Create HTTP client
            AsyncHttpClient client = new DefaultAsyncHttpClient();
            
            // Send asynchronous GET request
            return client.prepareGet(requestUrl)
                .setHeader("Accept", "application/text")
                .setHeader("Authorization", "Bearer " + apiKey)
                .execute()
                .toCompletableFuture()
                .thenApply(response -> {
                    try {
                        if (response.getStatusCode() == 200) {
                            return response.getResponseBody();
                        } else {
                            logger.error("Failed to retrieve DID document: {} {}", 
                                response.getStatusCode(), response.getResponseBody());
                            return null;
                        }
                    } finally {
                        try {
                            client.close();
                        } catch (Exception e) {
                            logger.warn("Failed to close HTTP client", e);
                        }
                    }
                });
        } catch (Exception e) {
            logger.error("Failed to get DID document: {}", e.getMessage(), e);
            return CompletableFuture.failedFuture(e);
        }
    }
    
    /**
     * Register DID document to DID service synchronously
     *
     * @param communicationServiceEndpoint Communication service endpoint for DID document
     * @param router Router's DID (optional, default is empty string)
     * @return Array containing [privateKeyPem, did, didDocumentJson]
     */
    public Object[] registerDidDocumentSync(String communicationServiceEndpoint, String router) {
        if (router == null) {
            router = "";
        }
        
        try {
            // Generate private key, public key, DID and DID document
            Object[] result = DIDGenerator.didGenerate(communicationServiceEndpoint, router);
            
            ECPrivateKey privateKey = (ECPrivateKey) result[0];
            String did = (String) result[2];
            String didDocumentJson = (String) result[3];
            
            // Convert private key to PEM format
            String privateKeyPem = CryptoTool.getPemFromPrivateKey(privateKey);
            
            // Prepare request headers
            Map<String, String> headers = new HashMap<>();
            headers.put("Content-Type", "application/text");
            headers.put("Authorization", "Bearer " + apiKey);
            
            // Create HTTP client
            try (AsyncHttpClient client = new DefaultAsyncHttpClient()) {
                // Send synchronous POST request
                Response response = client.preparePost(didServiceUrl + "/v1/did")
                    .setHeader("Content-Type", "application/text")
                    .setHeader("Authorization", "Bearer " + apiKey)
                    .setBody(didDocumentJson)
                    .execute()
                    .get();
                
                if (response.getStatusCode() == 200) {
                    return new Object[] { privateKeyPem, did, didDocumentJson };
                } else {
                    logger.error("Failed to create DID document: {} {}", 
                        response.getStatusCode(), response.getResponseBody());
                    return null;
                }
            }
        } catch (Exception e) {
            logger.error("Failed to register DID document synchronously: {}", e.getMessage(), e);
            throw new RuntimeException("Failed to register DID document", e);
        }
    }
    
    /**
     * Register DID document with a default empty router
     *
     * @param communicationServiceEndpoint Communication service endpoint for DID document
     * @return Array containing [privateKeyPem, did, didDocumentJson]
     */
    public Object[] registerDidDocumentSync(String communicationServiceEndpoint) {
        return registerDidDocumentSync(communicationServiceEndpoint, "");
    }
    
    /**
     * Get DID document from DID service synchronously
     *
     * @param did DID to resolve
     * @return DID document as a string
     */
    public String getDidDocumentSync(String did) {
        try {
            // Prepare request headers
            Map<String, String> headers = new HashMap<>();
            headers.put("Accept", "application/text");
            headers.put("Authorization", "Bearer " + apiKey);
            
            // Create HTTP client
            try (AsyncHttpClient client = new DefaultAsyncHttpClient()) {
                // Send synchronous GET request
                Response response = client.prepareGet(didServiceUrl + "/v1/did/" + did)
                    .setHeader("Accept", "application/text")
                    .setHeader("Authorization", "Bearer " + apiKey)
                    .execute()
                    .get();
                
                if (response.getStatusCode() == 200) {
                    return response.getResponseBody();
                } else {
                    logger.error("Failed to retrieve DID document: {} {}", 
                        response.getStatusCode(), response.getResponseBody());
                    return null;
                }
            }
        } catch (Exception e) {
            logger.error("Failed to get DID document synchronously: {}", e.getMessage(), e);
            throw new RuntimeException("Failed to get DID document", e);
        }
    }
} 