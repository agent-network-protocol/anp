package com.agentconnect.authentication;

import io.github.novacrypto.base58.Base58;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.util.encoders.Base64;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.util.Map;
import java.util.logging.Logger;
import java.util.logging.Level;

/**
 * EcdsaSecp256k1VerificationKey2019 implementation
 */
public class EcdsaSecp256k1VerificationKey2019 extends VerificationMethod {
    
    private static final Logger logger = Logger.getLogger(EcdsaSecp256k1VerificationKey2019.class.getName());
    private final ECPublicKeyParameters publicKey;
    public static final ECDomainParameters SECP256K1_PARAMS =
        new ECDomainParameters(
            CustomNamedCurves.getByName("secp256k1").getCurve(),
            CustomNamedCurves.getByName("secp256k1").getG(),
            CustomNamedCurves.getByName("secp256k1").getN(),
            CustomNamedCurves.getByName("secp256k1").getH()
        );
    
    public EcdsaSecp256k1VerificationKey2019(ECPublicKeyParameters publicKey) {
        this.publicKey = publicKey;
    }

    @Override
    public boolean verifySignature(byte[] content, String signature) {
        try {
            // Decode base64url signature
            byte[] signatureBytes = decodeBase64Url(signature);

            // Convert R|S format to DER format
            int rLength = signatureBytes.length / 2;
            BigInteger r = new BigInteger(1, java.util.Arrays.copyOfRange(signatureBytes, 0, rLength));
            BigInteger s = new BigInteger(1, java.util.Arrays.copyOfRange(signatureBytes, rLength, signatureBytes.length));

            // Double hash the content with SHA256 to match the signing process
            // First hash (matches DIDWBA.getSignatureResult())
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] firstHash = digest.digest(content);
            
            // Second hash (matches SHA256withECDSA in signCallback)
            digest.reset();
            byte[] doubleHash = digest.digest(firstHash);

            // Verify signature using double-hashed content
            ECDSASigner signer = new ECDSASigner();
            signer.init(false, publicKey);
            return signer.verifySignature(doubleHash, r, s);

        } catch (Exception e) {
            logger.log(Level.SEVERE, "Secp256k1 signature verification failed: " + e.getMessage(), e);
            return false;
        }
    }
    
    public static EcdsaSecp256k1VerificationKey2019 fromDict(Map<String, Object> methodDict) {
        if (methodDict.containsKey("publicKeyJwk")) {
            @SuppressWarnings("unchecked")
            Map<String, Object> jwk = (Map<String, Object>) methodDict.get("publicKeyJwk");
            return new EcdsaSecp256k1VerificationKey2019(extractPublicKeyFromJwk(jwk));
        } else if (methodDict.containsKey("publicKeyMultibase")) {
            String multibase = (String) methodDict.get("publicKeyMultibase");
            return new EcdsaSecp256k1VerificationKey2019(extractPublicKeyFromMultibase(multibase));
        }
        throw new IllegalArgumentException("Unsupported key format for EcdsaSecp256k1VerificationKey2019");
    }
    
    private static ECPublicKeyParameters extractPublicKeyFromJwk(Map<String, Object> jwk) {
        if (!"EC".equals(jwk.get("kty")) || !"secp256k1".equals(jwk.get("crv"))) {
            throw new IllegalArgumentException("Invalid JWK parameters for Secp256k1");
        }
        
        String xStr = (String) jwk.get("x");
        String yStr = (String) jwk.get("y");
        
        byte[] xBytes = decodeBase64Url(xStr);
        byte[] yBytes = decodeBase64Url(yStr);
        
        BigInteger x = new BigInteger(1, xBytes);
        BigInteger y = new BigInteger(1, yBytes);
        
        ECPoint point = SECP256K1_PARAMS.getCurve().createPoint(x, y);
        if (!point.isValid()) {
            throw new IllegalArgumentException("Point not on curve");
        }
        return new ECPublicKeyParameters(point, SECP256K1_PARAMS);
    }

    private static ECPublicKeyParameters extractPublicKeyFromMultibase(String multibase) {
        if (!multibase.startsWith("z")) {
            throw new IllegalArgumentException("Unsupported multibase encoding");
        }

        byte[] keyBytes = Base58.base58Decode(multibase.substring(1));
        ECPoint point = SECP256K1_PARAMS.getCurve().decodePoint(keyBytes);
        return new ECPublicKeyParameters(point, SECP256K1_PARAMS);
    }
    
    @Override
    public String encodeSignature(byte[] signatureBytes) {
        try {
            byte[] signature;
            
            // Try to parse DER format
            try {
                ASN1InputStream asn1InputStream = new ASN1InputStream(signatureBytes);
                ASN1Sequence sequence = (ASN1Sequence) asn1InputStream.readObject();
                asn1InputStream.close();
                
                ASN1Integer rInteger = (ASN1Integer) sequence.getObjectAt(0);
                ASN1Integer sInteger = (ASN1Integer) sequence.getObjectAt(1);
                
                BigInteger r = rInteger.getValue();
                BigInteger s = sInteger.getValue();
                
                // Convert to R|S format
                byte[] rBytes = r.toByteArray();
                byte[] sBytes = s.toByteArray();
                
                // Remove leading zero bytes if present
                if (rBytes.length > 32 && rBytes[0] == 0) {
                    rBytes = java.util.Arrays.copyOfRange(rBytes, 1, rBytes.length);
                }
                if (sBytes.length > 32 && sBytes[0] == 0) {
                    sBytes = java.util.Arrays.copyOfRange(sBytes, 1, sBytes.length);
                }
                
                signature = new byte[rBytes.length + sBytes.length];
                System.arraycopy(rBytes, 0, signature, 0, rBytes.length);
                System.arraycopy(sBytes, 0, signature, rBytes.length, sBytes.length);
                
            } catch (Exception e) {
                // If not DER format, assume it's already in R|S format
                if (signatureBytes.length % 2 != 0) {
                    throw new IllegalArgumentException("Invalid R|S signature format: length must be even");
                }
                signature = signatureBytes;
            }
            
            // Encode to base64url
            return encodeBase64Url(signature);
            
        } catch (Exception e) {
            logger.log(Level.SEVERE, "Failed to encode signature: " + e.getMessage(), e);
            throw new IllegalArgumentException("Invalid signature format: " + e.getMessage());
        }
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