package com.agentconnect.authentication;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.erdtman.jcs.JsonCanonicalizer;
import org.bitcoinj.core.Base58;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/** WBA key/document binding. It never replaces HTTPS provenance or permissions. */
public final class WbaDocumentBinding {
    private static final ObjectMapper JSON = new ObjectMapper();
    private WbaDocumentBinding() {}

    public static boolean authorized(Map<String, Object> document, String relationship, String keyId) {
        Object raw = document.get(relationship);
        if (!(raw instanceof List<?> entries)) return false;
        return entries.stream().anyMatch(entry -> keyId.equals(entry)
                || entry instanceof Map<?, ?> method && keyId.equals(method.get("id")));
    }

    @SuppressWarnings("unchecked")
    public static Map<String, Object> method(Map<String, Object> document, String keyId) {
        Object raw = document.get("verificationMethod");
        if (raw instanceof List<?> entries) {
            Map<String, Object> result = null;
            for (Object entry : entries) if (entry instanceof Map<?, ?> item && keyId.equals(item.get("id"))) {
                if (result != null) return null; // Duplicate IDs are not a key-selection policy.
                result = (Map<String, Object>) item;
            }
            return result;
        }
        return null;
    }

    @SuppressWarnings("unchecked")
    public static boolean validate(Map<String, Object> document) {
        try {
            if (!(document.get("id") instanceof String did) || !did.startsWith("did:wba:")
                    || Boolean.TRUE.equals(document.get("deactivated")) || !(document.get("verificationMethod") instanceof List<?>)) return false;
            PublicNetworkPolicy.didResource(did); // Syntax only, no network.
            String last = did.substring(did.lastIndexOf(':') + 1);
            boolean e1 = last.startsWith("e1_"), k1 = last.startsWith("k1_");
            if (!e1 && !k1) return true; // Plain/bare WBA authority is the trusted HTTPS resolver.
            if (!(document.get("proof") instanceof Map<?, ?> raw)) return false;
            Map<String, Object> proof = new HashMap<>((Map<String, Object>) raw);
            Object value = proof.remove("proofValue");
            boolean legacyK1 = k1 && "EcdsaSecp256k1Signature2019".equals(proof.get("type"));
            String purpose = (String) proof.get("proofPurpose");
            if (!(value instanceof String encoded) || encoded.length() > 256
                    || !(proof.get("verificationMethod") instanceof String keyId)
                    || !("assertionMethod".equals(purpose) || legacyK1 && "authentication".equals(purpose))
                    || !(proof.get("created") instanceof String) || !authorized(document, purpose, keyId)) return false;
            Map<String, Object> method = method(document, keyId);
            if (method == null || !did.equals(method.get("controller"))) return false;
            Map<String, Object> jwk = publicJwk(method);
            if (e1 && !("OKP".equals(jwk.get("kty")) && "Ed25519".equals(jwk.get("crv")))
                    || k1 && !("EC".equals(jwk.get("kty")) && "secp256k1".equals(jwk.get("crv")))) return false;
            String fingerprint = Base64.getUrlEncoder().withoutPadding().encodeToString(hash(canonical(jwk)));
            if (!last.substring(3).equals(fingerprint)) return false;
            if ("DataIntegrityProof".equals(proof.get("type"))) {
                if (!(e1 ? "eddsa-jcs-2022" : "didwba-jcs-ecdsa-secp256k1-2025").equals(proof.get("cryptosuite"))) return false;
            } else if (e1 || !"EcdsaSecp256k1Signature2019".equals(proof.get("type"))) return false;
            Map<String, Object> unsigned = new HashMap<>(document); unsigned.remove("proof");
            byte[] input = new byte[64];
            System.arraycopy(hash(canonical(proof)), 0, input, 0, 32);
            System.arraycopy(hash(canonical(unsigned)), 0, input, 32, 32);
            VerificationMethod verifier = VerificationMethod.fromDict(method);
            if (encoded.startsWith("z")) {
                try {
                    byte[] signature = Base58.decode(encoded.substring(1));
                    if (signature.length == 64) return verifier.verifySignature(input, Base64.getUrlEncoder().withoutPadding().encodeToString(signature));
                }
                catch (RuntimeException invalid) { /* Legacy base64url may also start with z. */ }
            }
            return verifier.verifySignature(input, encoded);
        } catch (Exception invalid) { return false; }
    }

    private static byte[] canonical(Map<String, Object> value) throws Exception {
        return new JsonCanonicalizer(JSON.writeValueAsString(value)).getEncodedString().getBytes(StandardCharsets.UTF_8);
    }
    private static byte[] hash(byte[] value) throws Exception { return MessageDigest.getInstance("SHA-256").digest(value); }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> publicJwk(Map<String, Object> method) {
        Map<String, Object> result = new HashMap<>();
        if (method.get("publicKeyJwk") instanceof Map<?, ?> raw) {
            Map<String, Object> source = (Map<String, Object>) raw;
            result.put("kty", source.get("kty")); result.put("crv", source.get("crv"));
            for (String field : "EC".equals(source.get("kty")) ? List.of("x", "y") : List.of("x")) {
                byte[] coordinate = Base64.getUrlDecoder().decode((String) source.get(field));
                if (coordinate.length == 33 && coordinate[0] == 0 && "EC".equals(source.get("kty"))) coordinate = Arrays.copyOfRange(coordinate, 1, 33);
                if (coordinate.length > 32 || coordinate.length == 0) throw new IllegalArgumentException("Invalid JWK coordinate");
                byte[] padded = new byte[32]; System.arraycopy(coordinate, 0, padded, 32 - coordinate.length, coordinate.length);
                result.put(field, Base64.getUrlEncoder().withoutPadding().encodeToString(padded));
            }
            return result;
        }
        if (method.get("publicKeyMultibase") instanceof String encoded && encoded.length() <= 100 && encoded.startsWith("z")) {
            byte[] bytes = Base58.decode(encoded.substring(1));
            if (bytes.length == 34 && bytes[0] == (byte) 0xed && bytes[1] == 1) {
                return Map.of("kty", "OKP", "crv", "Ed25519", "x", Base64.getUrlEncoder().withoutPadding().encodeToString(Arrays.copyOfRange(bytes, 2, 34)));
            }
        }
        throw new IllegalArgumentException("Unsupported binding key");
    }
}
