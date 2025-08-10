package com.agentconnect.test.example;

import com.agentconnect.authentication.DIDWBA;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.*;
import java.util.*;

public class DidWbaDocumentCreator {

    private static final Logger logger = LoggerFactory.getLogger(DidWbaDocumentCreator.class);

    static {
        // Add Bouncy Castle provider if not already added
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    /**
     * Create DID WBA document with keys
     *
     * @param hostname Server hostname
     * @param pathSegments Path segments for the DID
     * @param agentDescriptionUrl Agent description URL
     * @return DidDocumentResult containing the DID document and private keys
     */
    public static DidDocumentResult createDidWbaDocument(String hostname, List<String> pathSegments,
                                                        String agentDescriptionUrl) {
        try {
            // Create DID document
            Map<String, Object> didwbaDocument = DIDWBA.createDIDWBADocument(hostname, null, pathSegments, "");
            Map<String, Object> keyPairs = (Map<String, Object>) didwbaDocument.get("keys");
            Map<String, Object> didDocument = (Map<String, Object>) didwbaDocument.get("didDocument");            // Extract private key bytes
            Map<String, byte[]> privateKeys = new HashMap<>();
            for (Map.Entry<String, Object> entry : keyPairs.entrySet()) {
                String methodFragment = entry.getKey();
                byte[] privateKeyBytes =  entry.getValue().toString().getBytes();
                privateKeys.put(methodFragment, privateKeyBytes);
            }

            logger.info("Successfully created DID document with {} verification methods", keyPairs.size());

            return new DidDocumentResult(didDocument, privateKeys);

        } catch (Exception e) {
            logger.error("Failed to create DID WBA document", e);
            throw new RuntimeException("Failed to create DID WBA document", e);
        }
    }
    /**
     * Result container for DID document creation
     */
    public static class DidDocumentResult {
        private final Map<String, Object> didDocument;
        private final Map<String, byte[]> privateKeys;

        public DidDocumentResult(Map<String, Object> didDocument, Map<String, byte[]> privateKeys) {
            this.didDocument = didDocument;
            this.privateKeys = privateKeys;
        }

        public Map<String, Object> getDidDocument() { return didDocument; }
        public Map<String, byte[]> getPrivateKeys() { return privateKeys; }
    }
}