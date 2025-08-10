package com.agentconnect.utils;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.interfaces.ECPublicKey;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Utility class for verifying DID documents
 */
public class DIDVerifier {
    private static final Logger logger = LoggerFactory.getLogger(DIDVerifier.class);

    /**
     * Extract public key from DID document
     *
     * @param didDocument DID document
     * @param keyId       Key ID to extract
     * @return EC public key
     */
    @SuppressWarnings("unchecked")
    public static ECPublicKey extractPublicKey(Map<String, Object> didDocument, String keyId) {
        try {
            List<Map<String, Object>> verificationMethods = (List<Map<String, Object>>) didDocument.get("verificationMethod");
            
            for (Map<String, Object> vm : verificationMethods) {
                if (keyId.equals(vm.get("id")) && "EcdsaSecp256r1VerificationKey2019".equals(vm.get("type"))) {
                    String publicKeyHex = (String) vm.get("publicKeyHex");
                    return CryptoTool.getPublicKeyFromHex(publicKeyHex.substring(2), "secp256r1");
                }
            }
            
            throw new RuntimeException("Public key " + keyId + " not found in DID document");
        } catch (Exception e) {
            logger.error("Error extracting public key from DID document", e);
            throw new RuntimeException("Failed to extract public key from DID document", e);
        }
    }

    /**
     * Verify DID document
     *
     * @param didDocument DID document to verify
     * @return Map containing verification result (success or failure) and error message if applicable
     */
    @SuppressWarnings("unchecked")
    public static Map<String, Object> verifyDidDocument(Map<String, Object> didDocument) {
        Map<String, Object> result = new HashMap<>();
        
        try {
            // Extract signature-related data
            Map<String, Object> proof = (Map<String, Object>) didDocument.get("proof");
            String verificationMethod = (String) proof.get("verificationMethod");
            String signature = (String) proof.get("proofValue");

            // Extract public key
            ECPublicKey publicKey = extractPublicKey(didDocument, verificationMethod);

            // Extract DID
            String did = (String) didDocument.get("id");

            // Verify public key and DID
            boolean isDidValid = CryptoTool.verifyDidWithPublicKey(did, publicKey);
            if (!isDidValid) {
                result.put("success", false);
                result.put("error", "Public key is not valid for this DID");
                return result;
            }

            // Verify signature
            // Create a copy of the DID document without the proofValue to replicate the original message
            Map<String, Object> originalMessage = new HashMap<>(didDocument);
            Map<String, Object> proofCopy = new HashMap<>((Map<String, Object>) originalMessage.get("proof"));
            proofCopy.remove("proofValue");
            originalMessage.put("proof", proofCopy);

            boolean isSignatureValid = CryptoTool.verifySignatureForJson(publicKey, originalMessage, signature);

            if (isSignatureValid) {
                result.put("success", true);
                result.put("error", "");
            } else {
                result.put("success", false);
                result.put("error", "Signature verification failed");
            }

            return result;
        } catch (Exception e) {
            logger.error("Error verifying DID document", e);
            result.put("success", false);
            result.put("error", e.getMessage());
            return result;
        }
    }
} 