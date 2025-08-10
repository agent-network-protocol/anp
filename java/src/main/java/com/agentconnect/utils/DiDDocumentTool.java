package com.agentconnect.utils;

import com.agentconnect.authentication.DIDWBA;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.asynchttpclient.AsyncHttpClient;
import org.asynchttpclient.DefaultAsyncHttpClient;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;

/**
 * @Description
 * @Author yanliqing
 * @Date 2025/6/1 14:00
 */
public class DiDDocumentTool {
    private static final ObjectMapper objectMapper = new ObjectMapper();
    private static final Logger logger = LoggerFactory.getLogger(DiDDocumentTool.class);

    /**
     * Select authentication method from DID document.
     *
     * @param didDocument the DID document
     * @return map containing the selected method and fragment
     */
    @SuppressWarnings("unchecked")
    public static Map<String, Object> selectAuthenticationMethod(Map<String, Object> didDocument) {
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
     * Find verification method in DID document.
     *
     * @param didDocument the DID document
     * @param verificationMethodId the verification method ID
     * @return the verification method or null if not found
     */
    @SuppressWarnings("unchecked")
    public static Map<String, Object> findVerificationMethod(
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
     * Extract parts from an authentication header.
     *
     * @param authHeader the authentication header
     * @return array containing [did, methodFragment, nonce, timestamp, signature]
     */
    public static String[] extractAuthHeaderParts(String authHeader) {
        try {
            // Remove "DID " prefix if present
            if (authHeader.startsWith("DIDWba ")) {
                authHeader = authHeader.substring(7);
            }

            // Split by dots
            String[] parts = authHeader.split(",");
            if (parts.length != 5) {
                throw new IllegalArgumentException(
                        "Invalid auth header format: expected 5 parts, got " + parts.length);
            }

            return parts;
        } catch (Exception e) {
            logger.error("Failed to extract auth header parts: {}", e.getMessage(), e);
            throw new RuntimeException("Failed to extract auth header parts", e);
        }
    }


    /**
     * Resolves a DID WBA document synchronously.
     *
     * @param did the DID to resolve
     * @return the resolved DID document
     */
    public static Map<String, Object> resolveDIDWBADocumentSync(String did) {
        try {
            return resolveDIDWBADocument(did).get();
        } catch (Exception e) {
            logger.error("Failed to resolve DID document synchronously: {}", e.getMessage(), e);
            throw new RuntimeException("Failed to resolve DID document", e);
        }
    }

    /**
     * Resolves a DID WBA document asynchronously.
     *
     * @param did the DID to resolve
     * @return a CompletableFuture that will complete with the resolved DID document
     */
    public static CompletableFuture<Map<String, Object>> resolveDIDWBADocument(String did) {
        logger.info("Resolving DID document for: {}", did);

        // Validate DID format
        if (!did.startsWith("did:wba:")) {
            return CompletableFuture.failedFuture(
                    new IllegalArgumentException("Invalid DID format: must start with 'did:wba:'"));
        }

        // Extract domain and path from DID
        String[] didParts = did.split(":", 4);
        if (didParts.length < 3) {
            return CompletableFuture.failedFuture(
                    new IllegalArgumentException("Invalid DID format: missing domain"));
        }

        try {
            String domain = java.net.URLDecoder.decode(didParts[2], StandardCharsets.UTF_8);
            String[] pathSegments = new String[0];
            if (didParts.length > 3) {
                pathSegments = didParts[3].split(":");
            }

            // Create HTTP client
            AsyncHttpClient client = new DefaultAsyncHttpClient();

            // Create URL
            StringBuilder url = new StringBuilder();
            url.append("https://").append(domain);

            if (pathSegments.length > 0) {
                for (String segment : pathSegments) {
                    url.append('/').append(segment);
                }
                url.append("/did.json");
            } else {
                url.append("/.well-known/did.json");
            }

            logger.debug("Requesting DID document from URL: {}", url);

            // Send request
            return client.prepareGet(url.toString())
                    .execute()
                    .toCompletableFuture()
                    .thenApply(response -> {
                        try {
                            if (response.getStatusCode() == 200) {
                                String body = response.getResponseBody();
                                return objectMapper.readValue(body, Map.class);
                            } else {
                                throw new RuntimeException("Failed to resolve DID document: " +
                                        response.getStatusCode() + " " + response.getResponseBody());
                            }
                        } catch (Exception e) {
                            throw new RuntimeException("Failed to parse DID document", e);
                        } finally {
                            try {
                                client.close();
                            } catch (Exception e) {
                                logger.warn("Failed to close HTTP client", e);
                            }
                        }
                    });
        } catch (Exception e) {
            return CompletableFuture.failedFuture(e);
        }
    }

}
