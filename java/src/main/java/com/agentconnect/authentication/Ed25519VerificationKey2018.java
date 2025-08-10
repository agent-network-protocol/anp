package com.agentconnect.authentication;

import io.github.novacrypto.base58.Base58;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.crypto.signers.Ed25519Signer;
import org.bouncycastle.util.encoders.Base64;

import java.util.Map;
import java.util.logging.Logger;
import java.util.logging.Level;

/**
 * Ed25519VerificationKey2018 implementation
 */
public class Ed25519VerificationKey2018 extends VerificationMethod {
    
    private static final Logger logger = Logger.getLogger(Ed25519VerificationKey2018.class.getName());
    private final Ed25519PublicKeyParameters publicKey;
    
    public Ed25519VerificationKey2018(Ed25519PublicKeyParameters publicKey) {
        this.publicKey = publicKey;
    }
    
    @Override
    public boolean verifySignature(byte[] content, String signature) {
        try {
            byte[] signatureBytes = decodeBase64Url(signature);

            Ed25519Signer signer = new Ed25519Signer();
            signer.init(false, publicKey);
            signer.update(signatureBytes, 0, signatureBytes.length);
            return signer.verifySignature(content);
            
        } catch (Exception e) {
            logger.log(Level.SEVERE, "Ed25519 signature verification failed: " + e.getMessage(), e);
            return false;
        }
    }
    
    public static Ed25519VerificationKey2018 fromDict(Map<String, Object> methodDict) {
        if (methodDict.containsKey("publicKeyJwk")) {
            @SuppressWarnings("unchecked")
            Map<String, Object> jwk = (Map<String, Object>) methodDict.get("publicKeyJwk");
            return new Ed25519VerificationKey2018(extractPublicKeyFromJwk(jwk));
        } else if (methodDict.containsKey("publicKeyMultibase")) {
            String multibase = (String) methodDict.get("publicKeyMultibase");
            return new Ed25519VerificationKey2018(extractPublicKeyFromMultibase(multibase));
        } else if (methodDict.containsKey("publicKeyBase58")) {
            String base58Key = (String) methodDict.get("publicKeyBase58");
            return new Ed25519VerificationKey2018(extractPublicKeyFromBase58(base58Key));
        }
        throw new IllegalArgumentException("Unsupported key format for Ed25519VerificationKey2018");
    }
    
    private static Ed25519PublicKeyParameters extractPublicKeyFromJwk(Map<String, Object> jwk) {
        if (!"OKP".equals(jwk.get("kty")) || !"Ed25519".equals(jwk.get("crv"))) {
            throw new IllegalArgumentException("Invalid JWK parameters for Ed25519");
        }
        
        String xStr = (String) jwk.get("x");
        byte[] keyBytes = decodeBase64Url(xStr);
        return new Ed25519PublicKeyParameters(keyBytes, 0);
    }
    
    private static Ed25519PublicKeyParameters extractPublicKeyFromMultibase(String multibase) {
        if (!multibase.startsWith("z")) {
            throw new IllegalArgumentException("Unsupported multibase encoding");
        }
        byte[] keyBytes = Base58.base58Decode(multibase.substring(1));
        return new Ed25519PublicKeyParameters(keyBytes, 0);
    }
    
    private static Ed25519PublicKeyParameters extractPublicKeyFromBase58(String base58Key) {
        byte[] keyBytes = Base58.base58Decode(base58Key);
        return new Ed25519PublicKeyParameters(keyBytes, 0);
    }
    
    @Override
    public String encodeSignature(byte[] signatureBytes) {
        // Ed25519 uses raw signature
        return encodeBase64Url(signatureBytes);
    }
    
    private static byte[] decodeBase64Url(String input) {
        // Add padding if necessary
        String padded = input;
        while (padded.length() % 4 != 0) {
            padded += "=";
        }
        return Base64.decode(padded.replace('-', '+').replace('_', '/'));
    }
    
    private static String encodeBase64Url(byte[] input) {
        return Base64.toBase64String(input)
                .replace('+', '-')
                .replace('/', '_')
                .replaceAll("=+$", "");
    }
} 