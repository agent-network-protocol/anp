/**
 * @program: anp4java
 * @author: Ruitao.Zhai
 * @date: 2025-01-29
 */
package com.agentconnect.authentication;

import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.util.Map;
import java.util.logging.Logger;
import java.util.logging.Level;

public class EcdsaSecp256r1VerificationKey2019 extends VerificationMethod {
    
    private static final Logger logger = Logger.getLogger(EcdsaSecp256r1VerificationKey2019.class.getName());
    private final ECPublicKeyParameters publicKey;
    
    private static final ECNamedCurveParameterSpec CURVE_SPEC = ECNamedCurveTable.getParameterSpec("secp256r1");
    public static final ECDomainParameters SECP256R1_PARAMS = new ECDomainParameters(
        CURVE_SPEC.getCurve(),
        CURVE_SPEC.getG(),
        CURVE_SPEC.getN(),
        CURVE_SPEC.getH()
    );
    
    public EcdsaSecp256r1VerificationKey2019(ECPublicKeyParameters publicKey) {
        this.publicKey = publicKey;
    }

    @Override
    public boolean verifySignature(byte[] content, String signature) {
        try {
            byte[] signatureBytes = decodeBase64Url(signature);

            int rLength = signatureBytes.length / 2;
            BigInteger r = new BigInteger(1, java.util.Arrays.copyOfRange(signatureBytes, 0, rLength));
            BigInteger s = new BigInteger(1, java.util.Arrays.copyOfRange(signatureBytes, rLength, signatureBytes.length));

            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] firstHash = digest.digest(content);
            
            digest.reset();
            byte[] doubleHash = digest.digest(firstHash);

            ECDSASigner signer = new ECDSASigner();
            signer.init(false, publicKey);
            return signer.verifySignature(doubleHash, r, s);

        } catch (Exception e) {
            logger.log(Level.SEVERE, "Secp256r1 signature verification failed: " + e.getMessage(), e);
            return false;
        }
    }
    
    public static EcdsaSecp256r1VerificationKey2019 fromDict(Map<String, Object> methodDict) {
        if (methodDict.containsKey("publicKeyJwk")) {
            @SuppressWarnings("unchecked")
            Map<String, Object> jwk = (Map<String, Object>) methodDict.get("publicKeyJwk");
            return new EcdsaSecp256r1VerificationKey2019(extractPublicKeyFromJwk(jwk));
        } else if (methodDict.containsKey("publicKeyHex")) {
            String hex = (String) methodDict.get("publicKeyHex");
            return new EcdsaSecp256r1VerificationKey2019(extractPublicKeyFromHex(hex));
        }
        throw new IllegalArgumentException("Unsupported key format for EcdsaSecp256r1VerificationKey2019");
    }
    
    private static ECPublicKeyParameters extractPublicKeyFromJwk(Map<String, Object> jwk) {
        if (!"EC".equals(jwk.get("kty")) || !"P-256".equals(jwk.get("crv"))) {
            throw new IllegalArgumentException("Invalid JWK parameters for Secp256r1");
        }
        
        String xStr = (String) jwk.get("x");
        String yStr = (String) jwk.get("y");
        
        byte[] xBytes = decodeBase64Url(xStr);
        byte[] yBytes = decodeBase64Url(yStr);
        
        BigInteger x = new BigInteger(1, xBytes);
        BigInteger y = new BigInteger(1, yBytes);
        
        ECPoint point = SECP256R1_PARAMS.getCurve().createPoint(x, y);
        if (!point.isValid()) {
            throw new IllegalArgumentException("Point not on curve");
        }
        return new ECPublicKeyParameters(point, SECP256R1_PARAMS);
    }

    private static ECPublicKeyParameters extractPublicKeyFromHex(String hex) {
        byte[] keyBytes = Hex.decode(hex);
        
        // Handle various formats: raw EC point (65 bytes), X509 encoded, or malformed "04" + X509
        if (keyBytes.length == 65 && keyBytes[0] == 0x04) {
            // Already raw uncompressed EC point
            ECPoint point = SECP256R1_PARAMS.getCurve().decodePoint(keyBytes);
            return new ECPublicKeyParameters(point, SECP256R1_PARAMS);
        }
        
        // Handle "04" prefix + X509 format (common mistake in some implementations)
        // X509 starts with 0x30 (ASN.1 SEQUENCE)
        int x509Start = 0;
        if (keyBytes.length > 65 && keyBytes[0] == 0x04 && keyBytes[1] == 0x30) {
            x509Start = 1; // Skip the erroneous "04" prefix
        } else if (keyBytes[0] == 0x30) {
            x509Start = 0;
        } else {
            throw new IllegalArgumentException("Unknown public key format");
        }
        
        // Find the EC point within X509 structure
        // Look for 0x04 followed by exactly 64 bytes of coordinates
        for (int i = x509Start; i <= keyBytes.length - 65; i++) {
            if (keyBytes[i] == 0x04 && (keyBytes.length - i >= 65)) {
                byte[] rawPoint = java.util.Arrays.copyOfRange(keyBytes, i, i + 65);
                try {
                    ECPoint point = SECP256R1_PARAMS.getCurve().decodePoint(rawPoint);
                    if (point.isValid()) {
                        return new ECPublicKeyParameters(point, SECP256R1_PARAMS);
                    }
                } catch (Exception e) {
                    // Not a valid EC point at this position, continue searching
                }
            }
        }
        
        throw new IllegalArgumentException("Could not extract EC point from public key hex");
    }
    
    @Override
    public String encodeSignature(byte[] signatureBytes) {
        try {
            byte[] signature;
            
            try {
                ASN1InputStream asn1InputStream = new ASN1InputStream(signatureBytes);
                ASN1Sequence sequence = (ASN1Sequence) asn1InputStream.readObject();
                asn1InputStream.close();
                
                ASN1Integer rInteger = (ASN1Integer) sequence.getObjectAt(0);
                ASN1Integer sInteger = (ASN1Integer) sequence.getObjectAt(1);
                
                BigInteger r = rInteger.getValue();
                BigInteger s = sInteger.getValue();
                
                byte[] rBytes = r.toByteArray();
                byte[] sBytes = s.toByteArray();
                
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
                if (signatureBytes.length % 2 != 0) {
                    throw new IllegalArgumentException("Invalid R|S signature format: length must be even");
                }
                signature = signatureBytes;
            }
            
            return encodeBase64Url(signature);
            
        } catch (Exception e) {
            logger.log(Level.SEVERE, "Failed to encode signature: " + e.getMessage(), e);
            throw new IllegalArgumentException("Invalid signature format: " + e.getMessage());
        }
    }
    
    private static byte[] decodeBase64Url(String input) {
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
