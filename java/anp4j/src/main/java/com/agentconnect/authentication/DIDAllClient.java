/**
 * @program: anp4java
 * @author: Ruitao.Zhai
 * @date: 2025-01-29
 */
package com.agentconnect.authentication;

import com.agentconnect.utils.CryptoTool;
import com.agentconnect.utils.DIDGenerator;
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
    private final PublicHttpTransport.Transport transport;
    
    /**
     * Constructor
     *
     * @param didServiceUrl URL of the DID service
     * @param apiKey API key for the DID service
     */
    public DIDAllClient(String didServiceUrl, String apiKey) {
        this(didServiceUrl,apiKey,null);
    }

    /** The credential issuer endpoint is explicit trusted host configuration. */
    public DIDAllClient(String didServiceUrl,String apiKey,PublicHttpTransport.Transport transport) {
        this.didServiceUrl=didServiceUrl.replaceAll("/+$","");
        this.apiKey=apiKey;
        java.net.URI base=java.net.URI.create(this.didServiceUrl);
        PublicNetworkPolicy.validate(base,base);
        this.transport=transport!=null?transport:new PublicHttpTransport(base,java.time.Duration.ofSeconds(10)).asTransport();
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
        
        final String router=routerDid;
        return PublicHttpTransport.async(()->registerDidDocumentSync(communicationServiceEndpoint,router),java.time.Duration.ofSeconds(30));
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
        return PublicHttpTransport.async(()->getDidDocumentSync(did),java.time.Duration.ofSeconds(30));
    }
    
    /**
     * Register DID document to DID service synchronously
     *
     * @param communicationServiceEndpoint Communication service endpoint for DID document
     * @param router Router's DID (optional, default is empty string)
     * @return Array containing [privateKeyPem, did, didDocumentJson]
     */
    public Object[] registerDidDocumentSync(String communicationServiceEndpoint, String router) {
        Object[] generated=generateDidDocument(communicationServiceEndpoint,router);
        try {
            byte[] body=((String)generated[2]).getBytes(java.nio.charset.StandardCharsets.UTF_8);
            var response=transport.request(java.net.URI.create(didServiceUrl+"/v1/did"),"POST",Map.of("Content-Type","application/text","Authorization","Bearer "+apiKey),body);
            return response.status()==200?generated:null;
        } catch(java.io.IOException rejected) {throw new java.util.concurrent.CompletionException("DID registration rejected",rejected);}
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
        if(did==null||did.length()>4096||!did.startsWith("did:"))throw new IllegalArgumentException("Invalid DID lookup");
        String segment=java.net.URLEncoder.encode(did,java.nio.charset.StandardCharsets.UTF_8).replace("+","%20");
        try {
            var response=transport.request(java.net.URI.create(didServiceUrl+"/v1/did/"+segment),"GET",Map.of("Accept","application/text","Authorization","Bearer "+apiKey),new byte[0]);
            return response.status()==200?response.text():null;
        } catch(java.io.IOException rejected) {throw new java.util.concurrent.CompletionException("DID lookup rejected",rejected);}
    }
} 