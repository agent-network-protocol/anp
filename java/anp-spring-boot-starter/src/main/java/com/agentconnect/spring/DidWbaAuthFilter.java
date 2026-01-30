/**
 * @program: anp4java
 * @description: DID-WBA 认证过滤器
 * @author: Ruitao.Zhai
 * @date: 2025-01-21
 **/
package com.agentconnect.spring;

import com.agentconnect.authentication.DIDWBA;
import com.agentconnect.authentication.VerificationMethod;
import com.agentconnect.utils.DiDDocumentTool;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.erdtman.jcs.JsonCanonicalizer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.util.AntPathMatcher;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * DID-WBA 认证过滤器
 * 
 * 验证请求中的 Authorization 头，提取调用者 DID
 */
public class DidWbaAuthFilter extends OncePerRequestFilter {
    
    private static final Logger log = LoggerFactory.getLogger(DidWbaAuthFilter.class);
    private static final String DID_ATTRIBUTE = "anp.caller.did";
    private static final String AUTH_RESULT_ATTRIBUTE = "anp.auth.result";
    private static final ObjectMapper objectMapper = new ObjectMapper();
    
    // Maximum allowed timestamp age in seconds (5 minutes)
    private static final long MAX_TIMESTAMP_AGE_SECONDS = 300;
    
    private final DIDWBA didwba;
    private final List<String> exemptPaths;
    private final List<String> allowedDomains;
    private final AntPathMatcher pathMatcher = new AntPathMatcher();
    
    public DidWbaAuthFilter(List<String> exemptPaths, List<String> allowedDomains) {
        this.didwba = new DIDWBA();
        this.exemptPaths = new ArrayList<>(exemptPaths);
        this.allowedDomains = new ArrayList<>(allowedDomains);
        
        this.exemptPaths.add("/**/ad.json");
        this.exemptPaths.add("/**/interface.json");
        this.exemptPaths.add("/**/interface/*.json");
        this.exemptPaths.add("/health");
        this.exemptPaths.add("/actuator/**");
        this.exemptPaths.add("/error");
    }
    
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, 
                                    FilterChain filterChain) throws ServletException, IOException {
        String path = request.getRequestURI();
        
        if (isExempt(path)) {
            request.setAttribute(DID_ATTRIBUTE, "anonymous");
            filterChain.doFilter(request, response);
            return;
        }
        
        String authHeader = request.getHeader("Authorization");
        
        if (authHeader == null || authHeader.isEmpty()) {
            log.debug("No Authorization header for path: {}", path);
            request.setAttribute(DID_ATTRIBUTE, "anonymous");
            filterChain.doFilter(request, response);
            return;
        }
        
        try {
            Map<String, Object> authResult = verifyAuth(authHeader, request);
            
            if (authResult != null && authResult.containsKey("did")) {
                String callerDid = (String) authResult.get("did");
                request.setAttribute(DID_ATTRIBUTE, callerDid);
                request.setAttribute(AUTH_RESULT_ATTRIBUTE, authResult);
                log.debug("Authenticated request from DID: {}", callerDid);
            } else {
                request.setAttribute(DID_ATTRIBUTE, extractDidFromHeader(authHeader));
            }
            
            filterChain.doFilter(request, response);
            
        } catch (Exception e) {
            log.warn("Authentication failed for path {}: {}", path, e.getMessage());
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.setContentType("application/json");
            response.getWriter().write("{\"error\":\"Authentication failed\",\"message\":\"" + e.getMessage() + "\"}");
        }
    }
    
    private boolean isExempt(String path) {
        for (String pattern : exemptPaths) {
            if (pathMatcher.match(pattern, path)) {
                return true;
            }
        }
        return false;
    }
    
    private Map<String, Object> verifyAuth(String authHeader, HttpServletRequest request) {
        try {
            if (authHeader == null || authHeader.isEmpty()) {
                return null;
            }
            
            if (!authHeader.startsWith("DIDWba ") && !authHeader.startsWith("DID-WBA ")) {
                log.debug("Authorization header is not DID-WBA format");
                return null;
            }
            
            String headerContent = authHeader.startsWith("DIDWba ") 
                ? authHeader.substring(7) 
                : authHeader.substring(8);
            
            String[] parts = headerContent.split(",");
            if (parts.length != 5) {
                log.warn("Invalid DID-WBA header format: expected 5 parts, got {}", parts.length);
                return null;
            }
            
            String did = extractValue(parts[0], "did");
            String nonce = extractValue(parts[1], "nonce");
            String timestamp = extractValue(parts[2], "timestamp");
            String verificationMethodFragment = extractValue(parts[3], "verification_method");
            String signature = extractValue(parts[4], "signature");
            
            if (did == null || nonce == null || timestamp == null || 
                verificationMethodFragment == null || signature == null) {
                log.warn("Missing required fields in DID-WBA header");
                return null;
            }
            
            if (!isTimestampValid(timestamp)) {
                log.warn("Timestamp expired or invalid: {}", timestamp);
                Map<String, Object> result = new HashMap<>();
                result.put("did", did);
                result.put("verified", false);
                result.put("timestamp", timestamp);
                result.put("error", "Timestamp expired");
                return result;
            }
            
            String targetDomain = extractDomain(request.getRequestURL().toString());
            
            Map<String, Object> didDocument = DiDDocumentTool.resolveDIDWBADocumentSync(did);
            if (didDocument == null) {
                log.warn("Failed to resolve DID document for: {}", did);
                Map<String, Object> result = new HashMap<>();
                result.put("did", did);
                result.put("verified", false);
                result.put("timestamp", timestamp);
                result.put("error", "Failed to resolve DID document");
                return result;
            }
            
            Map<String, Object> verificationMethodInfo = DiDDocumentTool.selectAuthenticationMethod(didDocument);
            @SuppressWarnings("unchecked")
            Map<String, Object> method = (Map<String, Object>) verificationMethodInfo.get("method");
            
            Map<String, Object> dataToSign = new HashMap<>();
            dataToSign.put("nonce", nonce);
            dataToSign.put("timestamp", timestamp);
            dataToSign.put("service", targetDomain);
            dataToSign.put("did", did);
            
            String jsonString = objectMapper.writeValueAsString(dataToSign);
            JsonCanonicalizer canonicalizer = new JsonCanonicalizer(jsonString);
            String canonicalJson = canonicalizer.getEncodedString();
            
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hashedContent = digest.digest(canonicalJson.getBytes(StandardCharsets.UTF_8));
            
            VerificationMethod verifier = VerificationMethod.fromDict(method);
            boolean isValid = verifier.verifySignature(hashedContent, signature);
            
            Map<String, Object> result = new HashMap<>();
            result.put("did", did);
            result.put("verified", isValid);
            result.put("timestamp", timestamp);
            result.put("nonce", nonce);
            result.put("verification_method", verificationMethodFragment);
            
            if (!isValid) {
                result.put("error", "Signature verification failed");
            }
            
            log.debug("DID-WBA verification result for {}: {}", did, isValid);
            return result;
            
        } catch (Exception e) {
            log.error("Error verifying DID-WBA auth header: {}", e.getMessage(), e);
            Map<String, Object> result = new HashMap<>();
            result.put("verified", false);
            result.put("error", e.getMessage());
            return result;
        }
    }
    
    private String extractValue(String part, String expectedKey) {
        if (part == null) {
            return null;
        }
        String trimmed = part.trim();
        int eqIndex = trimmed.indexOf('=');
        if (eqIndex < 0) {
            return null;
        }
        String key = trimmed.substring(0, eqIndex).trim();
        if (!key.equals(expectedKey)) {
            log.debug("Expected key '{}' but got '{}'", expectedKey, key);
        }
        String value = trimmed.substring(eqIndex + 1).trim();
        if (value.startsWith("\"") && value.endsWith("\"")) {
            value = value.substring(1, value.length() - 1);
        }
        return value;
    }
    
    private boolean isTimestampValid(String timestamp) {
        try {
            Instant authTime = Instant.parse(timestamp);
            Instant now = Instant.now();
            long ageSeconds = ChronoUnit.SECONDS.between(authTime, now);
            return Math.abs(ageSeconds) <= MAX_TIMESTAMP_AGE_SECONDS;
        } catch (Exception e) {
            log.warn("Failed to parse timestamp: {}", timestamp);
            return false;
        }
    }
    
    private String extractDomain(String urlString) {
        try {
            URL url = new URL(urlString);
            return url.getHost();
        } catch (Exception e) {
            log.warn("Failed to extract domain from URL: {}", urlString);
            return urlString;
        }
    }
    
    private String extractDidFromHeader(String authHeader) {
        if (authHeader.startsWith("DID ")) {
            return authHeader.substring(4).trim();
        }
        if (authHeader.startsWith("DID-WBA ")) {
            String[] parts = authHeader.substring(8).split("\\.");
            if (parts.length > 0) {
                return "did:wba:" + parts[0];
            }
        }
        return "anonymous";
    }
    
    public static String getCallerDid(HttpServletRequest request) {
        Object did = request.getAttribute(DID_ATTRIBUTE);
        return did != null ? did.toString() : "anonymous";
    }
    
    @SuppressWarnings("unchecked")
    public static Map<String, Object> getAuthResult(HttpServletRequest request) {
        return (Map<String, Object>) request.getAttribute(AUTH_RESULT_ATTRIBUTE);
    }
}
