package com.agentconnect.authentication;

import java.util.Map;

/**
 * Abstract base class for verification methods
 */
public abstract class VerificationMethod {
    
    /**
     * Verify signature
     * @param content The content bytes to verify
     * @param signature The signature string
     * @return true if verification succeeds, false otherwise
     */
    public abstract boolean verifySignature(byte[] content, String signature);
    
    /**
     * Create instance from verification method dictionary in DID document
     * @param methodDict The verification method dictionary
     * @return VerificationMethod instance
     */
    public static VerificationMethod fromDict(Map<String, Object> methodDict) {
        String methodType = (String) methodDict.get("type");
        if (methodType == null) {
            throw new IllegalArgumentException("Missing verification method type");
        }
        
        switch (methodType) {
            case "EcdsaSecp256k1VerificationKey2019":
                return EcdsaSecp256k1VerificationKey2019.fromDict(methodDict);
            case "Ed25519VerificationKey2018":
                return Ed25519VerificationKey2018.fromDict(methodDict);
            default:
                throw new IllegalArgumentException("Unsupported verification method type: " + methodType);
        }
    }
    
    /**
     * Encode signature bytes to base64url format
     * @param signatureBytes Raw signature bytes
     * @return base64url encoded signature
     */
    public abstract String encodeSignature(byte[] signatureBytes);
} 