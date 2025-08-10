package com.agentconnect.test.example;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Map;

public class FileUtils {
    
    private static final Logger logger = LoggerFactory.getLogger(FileUtils.class);
    private static final ObjectMapper objectMapper = new ObjectMapper();
    
    /**
     * Save private keys and DID document to user directory
     *
     * @param uniqueId    User unique identifier
     * @param keys        Map of method fragment to private key bytes
     * @param didDocument DID document to save
     * @param didKeysPath
     * @return Path to the user directory
     */
    public static String savePrivateKeys(String uniqueId, Map<String,byte[]> keys, Map<String, Object> didDocument,
            String didKeysPath) {
        try {
            // Get current directory and create user directory
            Path currentDir = Paths.get(didKeysPath);
            Path userDir = currentDir.resolve("did_keys").resolve("user_" + uniqueId);
            
            // Create parent directories if they don't exist
            Files.createDirectories(userDir);
            
            // Save private keys
            for (Map.Entry<String, byte[]> entry : keys.entrySet()) {
                String methodFragment = entry.getKey();
                byte[] privateKey = entry.getValue();
                
                Path privateKeyPath = userDir.resolve(methodFragment + "_private.pem");
                Files.write(privateKeyPath, privateKey);
                logger.info("Saved private key '{}' to {}", methodFragment, privateKeyPath);
            }
            
            // Save DID document
            Path didPath = userDir.resolve("did.json");
            String didJson = objectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(didDocument);
            Files.write(didPath, didJson.getBytes());
            logger.info("Saved DID document to {}", didPath);
            
            return userDir.toString();
            
        } catch (IOException e) {
            logger.error("Failed to save private keys and DID document", e);
            throw new RuntimeException("Failed to save private keys and DID document", e);
        }
    }
    
    /**
     * Read DID document from file
     * 
     * @param didDocumentPath Path to DID document file
     * @return DID document as Map
     */
    @SuppressWarnings("unchecked")
    public static Map<String, Object> readDidDocument(String didDocumentPath) {
        try {
            Path path = Paths.get(didDocumentPath);
            String content = Files.readString(path);
            return objectMapper.readValue(content, Map.class);
        } catch (IOException e) {
            logger.error("Failed to read DID document from: {}", didDocumentPath, e);
            throw new RuntimeException("Failed to read DID document", e);
        }
    }
    
    /**
     * Read private key from file
     * 
     * @param privateKeyPath Path to private key file
     * @return Private key bytes
     */
    public static byte[] readPrivateKey(String privateKeyPath) {
        try {
            Path path = Paths.get(privateKeyPath);
            return Files.readAllBytes(path);
        } catch (IOException e) {
            logger.error("Failed to read private key from: {}", privateKeyPath, e);
            throw new RuntimeException("Failed to read private key", e);
        }
    }
    
    /**
     * Check if file exists
     * 
     * @param filePath Path to check
     * @return true if file exists
     */
    public static boolean fileExists(String filePath) {
        return Files.exists(Paths.get(filePath));
    }
    
    /**
     * Get absolute path
     * 
     * @param relativePath Relative path
     * @return Absolute path string
     */
    public static String getAbsolutePath(String relativePath) {
        return Paths.get(relativePath).toAbsolutePath().toString();
    }
}