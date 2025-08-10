package com.agentconnect.utils;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.HashMap;
import java.util.Map;

/**
 * Utility class for generating DID documents
 */
public class DIDGenerator {
    private static final Logger logger = LoggerFactory.getLogger(DIDGenerator.class);

    /**
     * Generate DID based on Bitcoin address
     *
     * @param bitcoinAddress Bitcoin address
     * @return DID string
     */
    public static String generateDid(String bitcoinAddress) {
        return "did:all:" + bitcoinAddress;
    }

    /**
     * Create DID document
     *
     * @param did             DID string
     * @param publicKey       EC public key
     * @param serviceEndpoint Service endpoint for the DID document
     * @param router          Router's DID
     * @return DID document as Map
     */
    public static Map<String, Object> createDidDocument(String did, ECPublicKey publicKey,
                                                        String serviceEndpoint, String router) {
        try {
            byte[] publicKeyBytes = publicKey.getEncoded();
            String publicKeyHex = "04" + CryptoTool.bytesToHex(publicKeyBytes);

            Map<String, Object> didDocument = new HashMap<>();
            didDocument.put("@context", "https://www.w3.org/ns/did/v1");
            didDocument.put("id", did);
            didDocument.put("controller", did);

            // Create verification method
            Map<String, Object> verificationMethod = new HashMap<>();
            verificationMethod.put("id", did + "#keys-1");
            verificationMethod.put("type", "EcdsaSecp256r1VerificationKey2019");
            verificationMethod.put("controller", did);
            verificationMethod.put("publicKeyHex", publicKeyHex);

            // Add to verification methods array
            didDocument.put("verificationMethod", new Object[]{verificationMethod});

            // Add authentication
            didDocument.put("authentication", new Object[]{verificationMethod});

            // Add service
            Map<String, Object> service = new HashMap<>();
            service.put("id", did + "#communication");
            service.put("type", "messageService");
            service.put("router", router);
            service.put("serviceEndpoint", serviceEndpoint);

            didDocument.put("service", new Object[]{service});

            return didDocument;
        } catch (Exception e) {
            logger.error("Error creating DID document", e);
            throw new RuntimeException("Failed to create DID document", e);
        }
    }

    /**
     * Sign DID document using secp256r1 private key
     *
     * @param privateKey   EC private key
     * @param didDocument  DID document to sign
     * @return Signed DID document
     */
    public static Map<String, Object> signDidDocumentSecp256r1(ECPrivateKey privateKey, Map<String, Object> didDocument) {
        try {
            // Format current time in ISO 8601 format
            String created = ZonedDateTime.now(ZoneId.of("UTC"))
                    .format(DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss'Z'"));

            // Create proof
            Map<String, Object> proof = new HashMap<>();
            proof.put("type", "EcdsaSecp256r1Signature2019");
            proof.put("created", created);
            proof.put("proofPurpose", "assertionMethod");
            proof.put("verificationMethod", didDocument.get("id") + "#keys-1");

            // Add proof to DID document for signing
            didDocument.put("proof", proof);

            // Sign the document
            String proofValue = CryptoTool.generateSignatureForJson(privateKey, didDocument);

            // Add signature to proof
            proof.put("proofValue", proofValue);
            didDocument.put("proof", proof);

            return didDocument;
        } catch (Exception e) {
            logger.error("Error signing DID document", e);
            throw new RuntimeException("Failed to sign DID document", e);
        }
    }

    /**
     * Generate DID and corresponding DID document
     *
     * @param communicationServiceEndpoint Communication service endpoint
     * @param router                       Router's DID (optional)
     * @param didServerDomain              DID server domain (optional)
     * @param didServerPort                DID server port (optional)
     * @return Array containing private key, public key, DID string, and DID document JSON
     */
    public static Object[] didGenerate(String communicationServiceEndpoint, String router,
                                      String didServerDomain, String didServerPort) {
        try {
            // Generate key pair
            ECPrivateKey privateKey = CryptoTool.generateSecp256r1PrivateKey();
            ECPublicKey publicKey = CryptoTool.generateSecp256r1PublicKey(privateKey);
            
            // Generate Bitcoin address
            String bitcoinAddress = CryptoTool.generateBitcoinAddress(publicKey);
            
            // Generate DID
            String did = generateDid(bitcoinAddress);
            
            // Add server domain and port if provided
            if (didServerDomain != null && !didServerDomain.isEmpty()) {
                did = did + "@" + didServerDomain;
                if (didServerPort != null && !didServerPort.isEmpty()) {
                    did = did + ":" + didServerPort;
                }
            }
            
            // Use the provided router or default to self-routing
            String effectiveRouter = (router != null && !router.isEmpty()) ? router : did;
            
            // Create and sign DID document
            Map<String, Object> didDocument = createDidDocument(did, publicKey, communicationServiceEndpoint, effectiveRouter);
            Map<String, Object> signedDidDocument = signDidDocumentSecp256r1(privateKey, didDocument);
            
            // Convert to JSON
            String didDocumentJson = new com.fasterxml.jackson.databind.ObjectMapper()
                    .writerWithDefaultPrettyPrinter()
                    .writeValueAsString(signedDidDocument);
            
            return new Object[]{privateKey, publicKey, did, didDocumentJson};
        } catch (Exception e) {
            logger.error("Error generating DID", e);
            throw new RuntimeException("Failed to generate DID", e);
        }
    }
    
    /**
     * Simplified version of didGenerate with minimal parameters
     *
     * @param communicationServiceEndpoint Communication service endpoint
     * @param router                       Router's DID (optional)
     * @return Array containing private key, public key, DID string, and DID document JSON
     */
    public static Object[] didGenerate(String communicationServiceEndpoint, String router) {
        return didGenerate(communicationServiceEndpoint, router, "", "");
    }
} 