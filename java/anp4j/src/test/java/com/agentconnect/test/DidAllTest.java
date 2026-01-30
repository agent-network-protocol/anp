package com.agentconnect.test;

import ch.qos.logback.classic.Level;
import com.agentconnect.authentication.DIDAllClient;
import com.agentconnect.authentication.DIDWbaAuthHeader;
import com.agentconnect.utils.LogBase;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

/**
 * Main class for demonstrating AgentConnect4Java functionality
 */
public class DidAllTest {
    private static final Logger logger = LoggerFactory.getLogger(DidAllTest.class);
    
    public static void main(String[] args) {
        try {
            // Initialize logging
            LogBase.setLogColorLevel(Level.INFO);
            
            logger.info("Starting AgentConnect4Java demonstration");
            
            // Path for saving generated files
            Path tempDir = Paths.get(System.getProperty("java.io.tmpdir"), "anp4java");
            Files.createDirectories(tempDir);
            
            // Example 1: Generate DID document using DIDAllClient
            logger.info("Example 1: Generating DID document using DIDAllClient");
            DIDAllClient didAllClient = new DIDAllClient("https://did.example.com", "fake-api-key");
            Object[] didResult = didAllClient.generateDidDocument("https://example.com/agent", "");
            
            String privateKeyPem = (String) didResult[0];
            String did = (String) didResult[1];
            String didDocumentJson = (String) didResult[2];
            
            logger.info("Generated DID: {}", did);
            
            // Save generated files
            Path privateKeyPath = Paths.get(tempDir.toString(), "private_key.pem");
            Path didDocumentPath = Paths.get(tempDir.toString(), "did_document.json");
            
            Files.writeString(privateKeyPath, privateKeyPem);
            Files.writeString(didDocumentPath, didDocumentJson);
            
            logger.info("Saved private key to: {}", privateKeyPath);
            logger.info("Saved DID document to: {}", didDocumentPath);
            
            // Example 2: Demonstrate DIDWbaAuthHeader
            logger.info("\nExample 2: Demonstrating DID authentication header generation");
            logger.info("Note: This is a demonstration only, not making actual HTTP requests");
            
            DIDWbaAuthHeader authHeader = new DIDWbaAuthHeader(
                    didDocumentPath.toString(),
                    privateKeyPath.toString()
            );
            
            // Get authentication header for a domain
            String serverUrl = "https://api.example.com";
            var headers = authHeader.getAuthHeader(serverUrl);
            
            logger.info("Generated authentication header for {}: {}", 
                    serverUrl, headers.get("Authorization"));
            
            logger.info("\nAgentConnect4Java demonstration completed successfully");
            
        } catch (Exception e) {
            logger.error("Error in demonstration", e);
        }
    }
} 