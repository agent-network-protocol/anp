package com.agentconnect.utils;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.novacrypto.base58.Base58;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.math.ec.ECPoint;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.security.*;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;

/**
 * Cryptographic utility methods for the AgentConnect system.
 */
public class CryptoTool {
    private static final Logger logger = LoggerFactory.getLogger(CryptoTool.class);
    private static final ObjectMapper objectMapper = new ObjectMapper();
    private static final SecureRandom secureRandom = new SecureRandom();
    
    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    /**
     * Generates random hexadecimal string of specified length.
     *
     * @param length The length in bytes (result will be twice this length in characters)
     * @return Random hex string
     */
    public static String generateRandomHex(int length) {
        byte[] bytes = new byte[length];
        secureRandom.nextBytes(bytes);
        return bytesToHex(bytes);
    }

    /**
     * Convert bytes to hex string
     *
     * @param bytes The bytes to convert
     * @return Hex string
     */
    public static String bytesToHex(byte[] bytes) {
        StringBuilder hexString = new StringBuilder();
        for (byte b : bytes) {
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) {
                hexString.append('0');
            }
            hexString.append(hex);
        }
        return hexString.toString();
    }

    /**
     * Generate a 16-character string from two random numbers using HKDF.
     *
     * @param randomNum1 First random number as string
     * @param randomNum2 Second random number as string
     * @return 16-character derived key as hex string
     */
    public static String generate16CharFromRandomNum(String randomNum1, String randomNum2) {
        try {
            byte[] content = (randomNum1 + randomNum2).getBytes();
            
            // Use HMAC-SHA256 as the pseudo-random function
            Mac mac = Mac.getInstance("HmacSHA256");
            SecretKeySpec keySpec = new SecretKeySpec(new byte[mac.getMacLength()], "HmacSHA256");
            mac.init(keySpec);
            
            // Extract step - Using a zero key with the content as salt
            byte[] prk = mac.doFinal(content);
            
            // Expand step - First block with counter 1
            ByteBuffer info = ByteBuffer.allocate(5);
            info.put((byte) 1); // Counter byte
            info.put("".getBytes()); // Optional context (empty in this case)
            info.flip();
            
            mac.init(new SecretKeySpec(prk, "HmacSHA256"));
            mac.update(info.array(), 0, info.remaining());
            byte[] derivedKey = Arrays.copyOf(mac.doFinal(), 8); // Take first 8 bytes
            
            return bytesToHex(derivedKey);
        } catch (Exception e) {
            logger.error("Error generating derived key", e);
            throw new RuntimeException("Failed to generate derived key", e);
        }
    }

    /**
     * Get hex representation of a public key
     *
     * @param publicKey The EC public key
     * @return Hex string of the public key
     */
    public static String getHexFromPublicKey(ECPublicKey publicKey) {
        try {
            byte[] encoded = publicKey.getEncoded();
            return bytesToHex(encoded);
        } catch (Exception e) {
            logger.error("Error converting public key to hex", e);
            throw new RuntimeException("Failed to convert public key to hex", e);
        }
    }

    /**
     * Get public key from hex representation
     *
     * @param publicKeyHex Hex string of the public key
     * @param curveName    Name of the elliptic curve (e.g., "secp256r1")
     * @return The reconstructed EC public key
     */
    public static ECPublicKey getPublicKeyFromHex(String publicKeyHex, String curveName) {
        try {
            byte[] publicKeyBytes = hexToBytes(publicKeyHex);
            KeyFactory keyFactory = KeyFactory.getInstance("EC", "BC");
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKeyBytes);
            return (ECPublicKey) keyFactory.generatePublic(keySpec);
        } catch (Exception e) {
            logger.error("Error creating public key from hex", e);
            throw new RuntimeException("Failed to create public key from hex", e);
        }
    }

    /**
     * Convert hex string to bytes
     *
     * @param hex The hex string
     * @return Byte array
     */
    public static byte[] hexToBytes(String hex) {
        int len = hex.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                    + Character.digit(hex.charAt(i + 1), 16));
        }
        return data;
    }

    /**
     * Generate a key pair for the specified elliptic curve
     *
     * @param curveName Name of the elliptic curve (e.g., "secp256r1")
     * @return Tuple containing private key, public key, and public key hex string
     */
    public static Map<String, Object> generateEcKeyPair(String curveName) {
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC", "BC");
            ECGenParameterSpec ecSpec = new ECGenParameterSpec(curveName);
            keyPairGenerator.initialize(ecSpec, secureRandom);
            
            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            ECPrivateKey privateKey = (ECPrivateKey) keyPair.getPrivate();
            ECPublicKey publicKey = (ECPublicKey) keyPair.getPublic();
            
            // Get the encoded point
            // ECNamedCurveParameterSpec params = ECNamedCurveTable.getParameterSpec(curveName);
            // ECPoint q = params.getCurve().decodePoint(publicKey.getEncoded());
            // String publicKeyHex = "04" + bytesToHex(q.getEncoded(false)).substring(2);
            
            Map<String, Object> result = new HashMap<>();
            result.put("privateKey", privateKey);
            result.put("publicKey", publicKey);
            // result.put("publicKeyHex", publicKeyHex);
            
            return result;
        } catch (Exception e) {
            logger.error("Error generating EC key pair", e);
            throw new RuntimeException("Failed to generate EC key pair", e);
        }
    }

    /**
     * Generate secp256r1 private key
     *
     * @return EC private key
     */
    public static ECPrivateKey generateSecp256r1PrivateKey() {
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC", "BC");
            ECGenParameterSpec ecSpec = new ECGenParameterSpec("secp256r1");
            keyPairGenerator.initialize(ecSpec, secureRandom);
            
            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            return (ECPrivateKey) keyPair.getPrivate();
        } catch (Exception e) {
            logger.error("Error generating secp256r1 private key", e);
            throw new RuntimeException("Failed to generate secp256r1 private key", e);
        }
    }

    /**
     * Generate public key from private key
     *
     * @param privateKey EC private key
     * @return EC public key
     */
    public static ECPublicKey generateSecp256r1PublicKey(ECPrivateKey privateKey) {
        try {
            KeyFactory keyFactory = KeyFactory.getInstance("EC", "BC");
            ECNamedCurveParameterSpec spec = ECNamedCurveTable.getParameterSpec("secp256r1");
            org.bouncycastle.math.ec.ECPoint q = spec.getG().multiply(privateKey.getS());
            ECPublicKeySpec pubSpec = new ECPublicKeySpec(q, spec);
            return (ECPublicKey) keyFactory.generatePublic(pubSpec);
        } catch (Exception e) {
            logger.error("Error generating public key from private key", e);
            throw new RuntimeException("Failed to generate public key from private key", e);
        }
    }

    /**
     * Generate Bitcoin address from public key
     *
     * @param publicKey EC public key
     * @return Bitcoin address
     */
    public static String generateBitcoinAddress(ECPublicKey publicKey) {
        try {
            // Get uncompressed public key bytes
            byte[] publicKeyBytes = publicKey.getEncoded();
            
            // SHA-256 hash
            MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
            byte[] sha256Hash = sha256.digest(publicKeyBytes);
            
            // RIPEMD-160 hash
            MessageDigest ripemd160 = MessageDigest.getInstance("RIPEMD160", "BC");
            byte[] ripemd160Hash = ripemd160.digest(sha256Hash);
            
            // Add version byte (0x00 for Bitcoin mainnet)
            byte[] versionedPayload = new byte[ripemd160Hash.length + 1];
            versionedPayload[0] = 0x00;
            System.arraycopy(ripemd160Hash, 0, versionedPayload, 1, ripemd160Hash.length);
            
            // Calculate checksum (first 4 bytes of double SHA-256)
            byte[] firstSha = sha256.digest(versionedPayload);
            byte[] doubleSha = sha256.digest(firstSha);
            byte[] checksum = Arrays.copyOfRange(doubleSha, 0, 4);
            
            // Append checksum to versioned payload
            byte[] addressBytes = new byte[versionedPayload.length + checksum.length];
            System.arraycopy(versionedPayload, 0, addressBytes, 0, versionedPayload.length);
            System.arraycopy(checksum, 0, addressBytes, versionedPayload.length, checksum.length);
            
            // Base58 encode
            return Base58.base58Encode(addressBytes);
        } catch (Exception e) {
            logger.error("Error generating Bitcoin address", e);
            throw new RuntimeException("Failed to generate Bitcoin address", e);
        }
    }

    /**
     * Generate signature for JSON document
     *
     * @param privateKey   EC private key
     * @param didDocument  DID document to sign
     * @return Base64 URL-safe encoded signature
     */
    public static String generateSignatureForJson(ECPrivateKey privateKey, Map<String, Object> didDocument) {
        try {
            // Convert document to canonical JSON string
            String didDocumentStr = objectMapper.writeValueAsString(didDocument);
            byte[] didDocumentBytes = didDocumentStr.getBytes();
            
            // Sign data
            Signature signature = Signature.getInstance("SHA256withECDSA", "BC");
            signature.initSign(privateKey);
            signature.update(didDocumentBytes);
            byte[] signatureBytes = signature.sign();
            
            // Encode to Base64URL
            String encodedSignature = Base64.getUrlEncoder().withoutPadding().encodeToString(signatureBytes);
            
            return encodedSignature;
        } catch (Exception e) {
            logger.error("Error generating signature for JSON", e);
            throw new RuntimeException("Failed to generate signature for JSON", e);
        }
    }

    /**
     * Verify signature for JSON document
     *
     * @param publicKey    EC public key
     * @param didDocument  DID document
     * @param signature    Base64 URL-safe encoded signature
     * @return true if signature is valid, false otherwise
     */
    public static boolean verifySignatureForJson(ECPublicKey publicKey, Map<String, Object> didDocument, String signature) {
        try {
            // Decode signature from Base64URL
            byte[] signatureBytes = Base64.getUrlDecoder().decode(signature + "==");
            
            // Convert document to canonical JSON string
            String didDocumentStr = objectMapper.writeValueAsString(didDocument);
            byte[] didDocumentBytes = didDocumentStr.getBytes();
            
            // Verify signature
            Signature verifier = Signature.getInstance("SHA256withECDSA", "BC");
            verifier.initVerify(publicKey);
            verifier.update(didDocumentBytes);
            
            return verifier.verify(signatureBytes);
        } catch (Exception e) {
            logger.error("Signature verification failed", e);
            return false;
        }
    }

    /**
     * Generate router JSON dictionary
     *
     * @param privateKey   EC private key
     * @param didDocument  DID document
     * @return Router JSON dictionary
     */
    public static Map<String, Object> generateRouterJson(ECPrivateKey privateKey, Map<String, Object> didDocument) {
        try {
            String routerDid = (String) didDocument.get("id");
            String nonce = generateRandomHex(32);
            
            // Format current time in ISO 8601 format
            String currentTime = ZonedDateTime.now(ZoneId.of("UTC"))
                    .format(DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss'Z'"));
            
            // Find verification method ID
            String verificationMethodId = null;
            List<Map<String, Object>> verificationMethods = (List<Map<String, Object>>) didDocument.get("verificationMethod");
            for (Map<String, Object> vm : verificationMethods) {
                if ("EcdsaSecp256r1VerificationKey2019".equals(vm.get("type"))) {
                    verificationMethodId = (String) vm.get("id");
                    break;
                }
            }
            
            // Create proof
            Map<String, Object> proof = new HashMap<>();
            proof.put("type", "EcdsaSecp256r1Signature2019");
            proof.put("created", currentTime);
            proof.put("proofPurpose", "assertionMethod");
            proof.put("verificationMethod", verificationMethodId);
            
            // Create router
            Map<String, Object> router = new HashMap<>();
            router.put("router", routerDid);
            router.put("nonce", nonce);
            router.put("proof", proof);
            
            // Sign router information
            String proofValue = generateSignatureForJson(privateKey, router);
            ((Map<String, Object>)router.get("proof")).put("proofValue", proofValue);
            
            return router;
        } catch (Exception e) {
            logger.error("Error generating router JSON", e);
            throw new RuntimeException("Failed to generate router JSON", e);
        }
    }

    /**
     * Verify if a public key matches a DID
     *
     * @param did        DID string
     * @param publicKey  EC public key
     * @return true if the public key matches the DID, false otherwise
     */
    public static boolean verifyDidWithPublicKey(String did, ECPublicKey publicKey) {
        try {
            // Extract Bitcoin address from DID
            String[] didParts = did.split(":");
            String bitcoinAddress = didParts[2].split("@")[0];
            
            // Generate Bitcoin address from public key
            String generatedAddress = generateBitcoinAddress(publicKey);
            
            // Compare addresses
            return bitcoinAddress.equals(generatedAddress);
        } catch (Exception e) {
            logger.error("Failed to verify DID with public key", e);
            return false;
        }
    }

    /**
     * Get PEM format string from EC private key
     *
     * @param privateKey EC private key
     * @return PEM encoded private key
     */
    public static String getPemFromPrivateKey(ECPrivateKey privateKey) {
        try {
            byte[] encoded = privateKey.getEncoded();
            String base64 = Base64.getEncoder().encodeToString(encoded);
            
            return "-----BEGIN PRIVATE KEY-----\n" +
                   formatBase64(base64) +
                   "-----END PRIVATE KEY-----\n";
        } catch (Exception e) {
            logger.error("Error converting private key to PEM", e);
            throw new RuntimeException("Failed to convert private key to PEM", e);
        }
    }
    
    /**
     * Load private key from PEM string
     *
     * @param pemStr PEM encoded private key
     * @return EC private key
     */
    public static ECPrivateKey loadPrivateKeyFromPem(String pemStr) {
        try {
            // Remove header and footer
            String pemContent = pemStr
                    .replace("-----BEGIN PRIVATE KEY-----", "")
                    .replace("-----END PRIVATE KEY-----", "")
                    .replaceAll("\\s", "");
            
            // Decode base64
            byte[] encoded = Base64.getDecoder().decode(pemContent);
            
            // Create private key
            KeyFactory keyFactory = KeyFactory.getInstance("EC", "BC");
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encoded);
            return (ECPrivateKey) keyFactory.generatePrivate(keySpec);
        } catch (Exception e) {
            logger.error("Error loading private key from PEM", e);
            throw new RuntimeException("Failed to load private key from PEM", e);
        }
    }
    
    /**
     * Format Base64 string with newlines every 64 characters
     *
     * @param base64 Base64 string
     * @return Formatted Base64 string
     */
    private static String formatBase64(String base64) {
        StringBuilder formatted = new StringBuilder();
        for (int i = 0; i < base64.length(); i += 64) {
            int endIndex = Math.min(i + 64, base64.length());
            formatted.append(base64, i, endIndex).append('\n');
        }
        return formatted.toString();
    }
    
    /**
     * Generate shared secret using ECDH
     *
     * @param privateKey     EC private key
     * @param peerPublicKey  Peer's EC public key
     * @return Shared secret as byte array
     */
    public static byte[] generateSharedSecret(ECPrivateKey privateKey, ECPublicKey peerPublicKey) {
        try {
            KeyAgreement keyAgreement = KeyAgreement.getInstance("ECDH", "BC");
            keyAgreement.init(privateKey);
            keyAgreement.doPhase(peerPublicKey, true);
            return keyAgreement.generateSecret();
        } catch (Exception e) {
            logger.error("Error generating shared secret", e);
            throw new RuntimeException("Failed to generate shared secret", e);
        }
    }
    
    /**
     * Encrypt data using AES-GCM
     *
     * @param data Data to encrypt
     * @param key  Encryption key
     * @return Map containing encrypted components
     */
    public static Map<String, String> encryptAesGcmSha256(byte[] data, byte[] key) {
        try {
            // Generate random IV
            byte[] iv = new byte[12];
            secureRandom.nextBytes(iv);
            
            // Initialize cipher
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", "BC");
            SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
            GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv);
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmSpec);
            
            // Encrypt data
            byte[] encryptedData = cipher.doFinal(data);
            
            // Encode components
            String encryptedBase64 = Base64.getEncoder().encodeToString(encryptedData);
            String ivBase64 = Base64.getEncoder().encodeToString(iv);
            
            // Create result map
            Map<String, String> result = new HashMap<>();
            result.put("encrypted", encryptedBase64);
            result.put("iv", ivBase64);
            result.put("algorithm", "A256GCM");
            
            return result;
        } catch (Exception e) {
            logger.error("Error encrypting data", e);
            throw new RuntimeException("Failed to encrypt data", e);
        }
    }
    
    /**
     * Decrypt data using AES-GCM
     *
     * @param encryptedJson Map containing encrypted components
     * @param key           Decryption key
     * @return Decrypted data as string
     */
    public static String decryptAesGcmSha256(Map<String, String> encryptedJson, byte[] key) {
        try {
            // Decode components
            byte[] encryptedData = Base64.getDecoder().decode(encryptedJson.get("encrypted"));
            byte[] iv = Base64.getDecoder().decode(encryptedJson.get("iv"));
            
            // Initialize cipher
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", "BC");
            SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
            GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv);
            cipher.init(Cipher.DECRYPT_MODE, keySpec, gcmSpec);
            
            // Decrypt data
            byte[] decryptedData = cipher.doFinal(encryptedData);
            
            return new String(decryptedData);
        } catch (Exception e) {
            logger.error("Error decrypting data", e);
            throw new RuntimeException("Failed to decrypt data", e);
        }
    }
} 