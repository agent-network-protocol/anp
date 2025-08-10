package com.agentconnect.authentication;

import com.agentconnect.utils.CryptoTool;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.math.ec.ECPoint;
import org.erdtman.jcs.JsonCanonicalizer;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.math.BigInteger;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.*;

import static com.agentconnect.authentication.EcdsaSecp256k1VerificationKey2019.SECP256K1_PARAMS;

/**
 * The DIDWBA class provides utilities for working with Web DID Authentication.
 */
public class DIDWBA {
    private static final Logger logger = LoggerFactory.getLogger(DIDWBA.class);
    private static final ObjectMapper objectMapper = new ObjectMapper();
    
    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    /**
     * Creates a DID WBA document.
     * 
     * @param hostname the hostname
     * @param port the port (optional)
     * @param pathSegments the path segments (optional)
     * @param agentDescriptionUrl the agent description URL (optional)
     * @return a map containing the DID document and keys
     */
    public static Map<String, Object> createDIDWBADocument(
            String hostname,
            Integer port,
            List<String> pathSegments,
            String agentDescriptionUrl) {
        
        if (hostname == null || hostname.isEmpty()) {
            throw new IllegalArgumentException("Hostname cannot be empty");
        }
        
        if (isIpAddress(hostname)) {
            throw new IllegalArgumentException("Hostname cannot be an IP address");
        }
        
        logger.info("Creating DID WBA document for hostname: {}", hostname);
        
        // Build base DID
        String didBase = "did:wba:" + hostname;
        if (port != null) {
            String encodedPort = URLEncoder.encode(":" + port, StandardCharsets.UTF_8);
            didBase = didBase + encodedPort;
            logger.debug("Added port to DID base: {}", didBase);
        }
        
        String did = didBase;
        if (pathSegments != null && !pathSegments.isEmpty()) {
            String didPath = String.join(":", pathSegments);
            did = didBase + ":" + didPath;
            logger.debug("Added path segments to DID: {}", did);
        }
        
        try {
            // Generate secp256k1 key pair
            logger.debug("Generating secp256k1 key pair");
            Map<String, Object> keyPair = CryptoTool.generateEcKeyPair("secp256k1");
            ECPrivateKey privateKey = (ECPrivateKey) keyPair.get("privateKey");
            ECPublicKey publicKey = (ECPublicKey) keyPair.get("publicKey");
            
            // Build verification method
            Map<String, Object> verificationMethod = new HashMap<>();
            verificationMethod.put("id", did + "#key-1");
            verificationMethod.put("type", "EcdsaSecp256k1VerificationKey2019");
            verificationMethod.put("controller", did);
            verificationMethod.put("publicKeyJwk", publicKeyToJwk(publicKey));
            
            // Build DID document
            Map<String, Object> didDocument = new HashMap<>();
            didDocument.put("@context", Arrays.asList(
                "https://www.w3.org/ns/did/v1",
                "https://w3id.org/security/suites/jws-2020/v1",
                "https://w3id.org/security/suites/secp256k1-2019/v1"
            ));
            didDocument.put("id", did);
            didDocument.put("verificationMethod", Collections.singletonList(verificationMethod));
            didDocument.put("authentication", Collections.singletonList(verificationMethod.get("id")));
            
            // Add agent description if URL is provided
            if (agentDescriptionUrl != null) {
                Map<String, Object> service = new HashMap<>();
                service.put("id", did + "#ad");
                service.put("type", "AgentDescription");
                service.put("serviceEndpoint", agentDescriptionUrl);
                
                didDocument.put("service", Collections.singletonList(service));
            }
            
            // Build keys dictionary
            Map<String, Object> keys = new HashMap<>();
            keys.put("key-1", CryptoTool.getPemFromPrivateKey(privateKey));
            
            // Return result
            Map<String, Object> result = new HashMap<>();
            result.put("didDocument", didDocument);
            result.put("keys", keys);
            
            logger.info("Successfully created DID document with ID: {}", did);
            return result;
        } catch (Exception e) {
            logger.error("Failed to create DID WBA document: {}", e.getMessage(), e);
            throw new RuntimeException("Failed to create DID WBA document", e);
        }
    }

    /**
     * Functional interface for signing callback
     */
    @FunctionalInterface
    public interface SignCallback {
        byte[] sign(byte[] content, String methodFragment);
    }

    /**
     * Generate authentication header for DID document.
     * 
     * @param didDocument the DID document
     * @param serviceDomain the service domain
     * @param signCallback the signing callback
     * @return the authentication header
     */
    public static String generateAuthHeader(
            Map<String, Object> didDocument,
            String serviceDomain,
            SignCallback signCallback) {
        
        try {
            logger.info("Generating auth header for DID: {} and domain: {}", 
                didDocument.get("id"), serviceDomain);
            
            // Find a suitable verification method
            Map<String, Object> verificationMethodInfo = selectAuthenticationMethod(didDocument);
            String methodFragment = (String) verificationMethodInfo.get("fragment");
            
            // Get DID
            String did = (String) didDocument.get("id");
            if( did == null|| did.isEmpty() ) {
                throw new IllegalArgumentException("DID document missing id field");
            }
            
            // Generate nonce
            String nonce = UUID.randomUUID().toString();
            
            // Get current timestamp
            long epochSecond = Instant.now().getEpochSecond();
            String timestamp = Instant.ofEpochSecond(epochSecond).atZone(ZoneOffset.UTC)
                    .format(DateTimeFormatter.ISO_INSTANT);

            // 构建要签名的数据
            Map<String, Object> dataToSign = new HashMap<>();
            dataToSign.put("nonce", nonce);
            dataToSign.put("timestamp", timestamp);
            dataToSign.put("service", serviceDomain);
            dataToSign.put("did", did);

            String signature = getSignatureResult(dataToSign,verificationMethodInfo,signCallback);

            // Create auth header using the new standard format
            return constructAuthorizationHeader(did, nonce, timestamp, methodFragment, signature);
        } catch (Exception e) {
            logger.error("Failed to generate auth header: {}", e.getMessage(), e);
            throw new RuntimeException("Failed to generate auth header", e);
        }
    }

    /**
     * Checks if a hostname is an IP address.
     *
     * @param hostname the hostname to check
     * @return true if the hostname is an IP address, false otherwise
     */
    private static boolean isIpAddress(String hostname) {
        // IPv4 pattern
        String ipv4Pattern = "^(\\d{1,3}\\.){3}\\d{1,3}$";
        // IPv6 pattern (simplified)
        String ipv6Pattern = "^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$";

        return hostname.matches(ipv4Pattern) || hostname.matches(ipv6Pattern);
    }

    /**
     * Encodes bytes data to base64url format.
     *
     * @param data the bytes to encode
     * @return the base64url encoded string
     */
    private static String encodeBase64url(byte[] data) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(data);
    }

    /**
     * Converts a secp256k1 public key to JWK format.
     *
     * @param publicKey the public key to convert
     * @return the JWK as a map
     */
    private static Map<String, Object> publicKeyToJwk(ECPublicKey publicKey) {
        try {
            // 使用 Bouncy Castle 提取 EC 公钥的坐标
            ECPublicKeyParameters ecPublicKey = new ECPublicKeyParameters(
                    ((BCECPublicKey) publicKey).getQ(),
                    SECP256K1_PARAMS
            );
            ECPoint point = ecPublicKey.getQ();
            BigInteger x = point.getAffineXCoord().toBigInteger();
            BigInteger y = point.getAffineYCoord().toBigInteger();

            // 生成 kid（可选）
            byte[] keyId = MessageDigest.getInstance("SHA-256").digest(publicKey.getEncoded());

            Map<String, Object> jwk = new HashMap<>();
            jwk.put("kty", "EC");
            jwk.put("crv", "secp256k1");
            jwk.put("x", encodeBase64url(x.toByteArray()));
            jwk.put("y", encodeBase64url(y.toByteArray()));
            jwk.put("kid", encodeBase64url(keyId));

            return jwk;
        } catch (Exception e) {
            logger.error("Failed to convert public key to JWK: {}", e.getMessage(), e);
            throw new RuntimeException("Failed to convert public key to JWK", e);
        }
    }

    /**
     * Find verification method in DID document.
     *
     * @param didDocument the DID document
     * @param verificationMethodId the verification method ID
     * @return the verification method or null if not found
     */
    @SuppressWarnings("unchecked")
    private static Map<String, Object> findVerificationMethod(
            Map<String, Object> didDocument,
            String verificationMethodId) {

        List<Map<String, Object>> verificationMethods =
                (List<Map<String, Object>>) didDocument.get("verificationMethod");

        if (verificationMethods != null) {
            for (Map<String, Object> method : verificationMethods) {
                if (verificationMethodId.equals(method.get("id"))) {
                    return method;
                }
            }
        }

        return null;
    }

    /**
     * Select authentication method from DID document.
     *
     * @param didDocument the DID document
     * @return map containing the selected method and fragment
     */
    @SuppressWarnings("unchecked")
    private static Map<String, Object> selectAuthenticationMethod(Map<String, Object> didDocument) {
        List<Object> authentications = (List<Object>) didDocument.get("authentication");
        if (authentications == null || authentications.isEmpty()) {
            throw new IllegalArgumentException("No authentication methods found in DID document");
        }

        // Try to find the first valid authentication method
        for (Object auth : authentications) {
            String authId;
            Map<String, Object> method;

            if (auth instanceof String) {
                // Reference to method
                authId = (String) auth;
                method = findVerificationMethod(didDocument, authId);
            } else if (auth instanceof Map) {
                // Embedded method
                method = (Map<String, Object>) auth;
                authId = (String) method.get("id");
                if (authId == null) {
                    throw new RuntimeException("Embedded verification method missing 'id' field");
                }
            } else {
                continue;
            }

            if (method != null) {
                // Extract fragment
                String methodId = (String) method.get("id");
                String fragment = methodId.substring(methodId.indexOf("#") + 1);

                Map<String, Object> result = new HashMap<>();
                result.put("method", method);
                result.put("fragment", fragment);

                return result;
            }
        }

        throw new IllegalArgumentException("No valid authentication methods found in DID document");
    }

    /**
     * Generate signature result based on data to sign and verification method info.
     * @param dataToSign
     * @param verificationMethodInfo
     * @param signCallback
     * @return
     * @throws IOException
     * @throws NoSuchAlgorithmException
     */
    private static String getSignatureResult(Map<String, Object> dataToSign,
            Map<String, Object> verificationMethodInfo,
            SignCallback signCallback) throws IOException, NoSuchAlgorithmException {
        String methodFragment = (String) verificationMethodInfo.get("fragment");
        Map<String,Object> method = (Map<String, Object>) verificationMethodInfo.get("method");

        String jsonString = objectMapper.writeValueAsString(dataToSign);
        // 使用JCS进行JSON规范化
        JsonCanonicalizer canonicalizer = new JsonCanonicalizer(jsonString);
        String canonicalJson = canonicalizer.getEncodedString();
        logger.debug("generate_auth_header Canonical JSON: {}", canonicalJson);

        // 计算SHA-256哈希
        MessageDigest digest = MessageDigest.getInstance("SHA-256");

        // Sign content
        byte[] signature_bytes = signCallback.sign(digest.digest(canonicalJson.getBytes("UTF-8")), methodFragment);

        VerificationMethod verifier = VerificationMethod.fromDict(method);

        return verifier.encodeSignature(signature_bytes);
    }

    /**
     * Construct DIDWba authorization header in the standard format.
     * 
     * @param did DID identifier
     * @param nonce Random nonce value
     * @param timestamp Unix timestamp
     * @param verificationMethodFragment Verification method fragment
     * @param signature Base64-encoded signature
     * @return Formatted authorization header string
     */
    private static String constructAuthorizationHeader(String did, String nonce, String timestamp,
                                                    String verificationMethodFragment, String signature) {
        return String.format("DIDWba did=\"%s\", nonce=\"%s\", timestamp=\"%s\", " +
                            "verification_method=\"%s\", signature=\"%s\"",
                            did, nonce, timestamp, verificationMethodFragment, signature);
    }
} 