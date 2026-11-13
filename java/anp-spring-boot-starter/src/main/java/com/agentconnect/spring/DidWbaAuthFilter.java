package com.agentconnect.spring;

import com.agentconnect.authentication.DIDWBA;
import com.agentconnect.authentication.LegacyAuthSecurity;
import com.agentconnect.authentication.PublicNetworkPolicy;
import com.agentconnect.utils.DiDDocumentTool;
import org.springframework.util.AntPathMatcher;
import org.springframework.web.filter.OncePerRequestFilter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URI;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import java.util.function.Function;

/** Complete Legacy authentication. Never project an unverified header as a DID. */
public class DidWbaAuthFilter extends OncePerRequestFilter {
    private static final String DID_ATTRIBUTE = "anp.caller.did";
    private static final String AUTH_RESULT_ATTRIBUTE = "anp.auth.result";
    private final List<String> exemptPaths;
    private final java.util.Set<String> receiverOrigins;
    private final AntPathMatcher pathMatcher = new AntPathMatcher();
    private final LegacyAuthSecurity.Policy policy;
    private final LegacyAuthSecurity.ReplayStore replayStore;
    private final Function<String, CompletableFuture<Map<String, Object>>> resolver;

    public DidWbaAuthFilter(List<String> exemptPaths, List<String> allowedDomains) {
        this(exemptPaths, allowedDomains, LegacyAuthSecurity.Policy.realtime(),
                new LegacyAuthSecurity.MemoryReplayStore(), DiDDocumentTool::resolveDIDWBADocument);
    }

    /** Shared stores/resolvers are explicit host dependencies, injectable in units. */
    public DidWbaAuthFilter(List<String> exemptPaths, List<String> allowedDomains,
            LegacyAuthSecurity.Policy policy, LegacyAuthSecurity.ReplayStore store,
            Function<String, CompletableFuture<Map<String, Object>>> resolver) {
        if (policy == null || !policy.checkTime() || store == null || resolver == null) throw new IllegalArgumentException("Invalid authentication dependencies");
        this.policy = policy; this.replayStore = store; this.resolver = resolver;
        this.exemptPaths = new ArrayList<>(exemptPaths);
        this.receiverOrigins = allowedDomains.stream().map(value -> {
            URI origin = URI.create(value.contains("://") ? value : "https://"+value);
            if (!"https".equals(origin.getScheme())) throw new IllegalArgumentException("Receiver origins must use HTTPS");
            return PublicNetworkPolicy.origin(origin);
        }).collect(java.util.stream.Collectors.toUnmodifiableSet());
        this.exemptPaths.addAll(List.of("/**/ad.json", "/**/interface.json", "/**/interface/*.json", "/health", "/actuator/**", "/error"));
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
            FilterChain filterChain) throws ServletException, IOException {
        request.removeAttribute(DID_ATTRIBUTE);
        request.removeAttribute(AUTH_RESULT_ATTRIBUTE);
        if (exemptPaths.stream().anyMatch(pattern -> pathMatcher.match(pattern, request.getRequestURI()))) {
            request.setAttribute(DID_ATTRIBUTE, "anonymous");
            filterChain.doFilter(request, response);
            return;
        }
        List<String> authorizations = Collections.list(request.getHeaders("Authorization"));
        if (authorizations.size() != 1 || authorizations.get(0).isBlank()) { reject(response, 401); return; }
        Map<String, Object> result;
        try {
            Map<String, String> parts = DIDWBA.extractAuthHeaderParts(authorizations.get(0));
            policy.validateTimestamp(parts.get("timestamp")); // Reject stale samples before network IO.
            URI target = URI.create(request.getRequestURL().toString());
            String scope = PublicNetworkPolicy.origin(target);
            String domain = target.getHost().toLowerCase(Locale.ROOT);
            if (!receiverOrigins.contains(scope)) throw new SecurityException("Receiver origin is not configured or approved");
            Map<String, Object> document = resolver.apply(parts.get("did")).get(10, TimeUnit.SECONDS);
            result = DIDWBA.authenticateAsync(authorizations.get(0), document, domain, scope, policy, replayStore).get(10, TimeUnit.SECONDS);
            if (!Boolean.TRUE.equals(result.get("verified")) || !(result.get("did") instanceof String)) throw new SecurityException("Unverified identity");
        } catch (Exception failure) {
            if(failure instanceof InterruptedException)Thread.currentThread().interrupt();
            Throwable cause = failure;
            while (cause.getCause() != null && cause != cause.getCause()) cause = cause.getCause();
            boolean unavailable = failure instanceof java.util.concurrent.TimeoutException
                    || cause instanceof LegacyAuthSecurity.ReplayUnavailable
                    || failure.getCause() instanceof LegacyAuthSecurity.ReplayUnavailable;
            reject(response, unavailable ? 503 : 401);
            return;
        }
        request.setAttribute(DID_ATTRIBUTE, result.get("did"));
        request.setAttribute(AUTH_RESULT_ATTRIBUTE, result);
        filterChain.doFilter(request, response);
    }

    private static void reject(HttpServletResponse response, int status) throws IOException {
        response.setStatus(status);
        response.setContentType("application/json");
        response.getWriter().write(status == 503 ? "{\"error\":\"Authentication temporarily unavailable\"}" : "{\"error\":\"Authentication failed\"}");
    }

    public static String getCallerDid(HttpServletRequest request) {
        Object did = request.getAttribute(DID_ATTRIBUTE);
        Map<String, Object> result = getAuthResult(request);
        return did instanceof String && result != null && Boolean.TRUE.equals(result.get("verified")) ? (String) did : "anonymous";
    }

    @SuppressWarnings("unchecked")
    public static Map<String, Object> getAuthResult(HttpServletRequest request) {
        Object value = request.getAttribute(AUTH_RESULT_ATTRIBUTE);
        return value instanceof Map<?, ?> ? (Map<String, Object>) value : null;
    }
}
