package com.agentconnect.authentication;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Clock;
import java.time.Instant;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Stateless Legacy policy and atomic replay adapters. No database or network IO. */
public final class LegacyAuthSecurity {
    private LegacyAuthSecurity() {}

    public record Policy(Clock clock, long maxAgeSeconds, long futureSkewSeconds, boolean checkTime) {
        public Policy {
            if (clock == null || maxAgeSeconds < 1 || maxAgeSeconds > 86400
                    || futureSkewSeconds < 0 || futureSkewSeconds > 86400) {
                throw new IllegalArgumentException("Invalid Legacy authentication policy");
            }
        }
        public static Policy realtime() { return new Policy(Clock.systemUTC(), 300, 60, true); }
        public Instant validateTimestamp(String timestamp) {
            if (timestamp == null || timestamp.length() > 64) throw new SecurityException("Invalid authentication timestamp");
            final Instant created;
            try { created = Instant.parse(timestamp); }
            catch (RuntimeException invalid) { throw new SecurityException("Invalid authentication timestamp"); }
            Instant now = clock.instant();
            if (checkTime && (created.isAfter(now.plusSeconds(futureSkewSeconds))
                    || now.isAfter(created.plusSeconds(maxAgeSeconds)))) {
                throw new SecurityException("Authentication timestamp expired or invalid");
            }
            return created.plusSeconds(maxAgeSeconds);
        }
    }

    /** Verified facts only. Storage must retain the key through validUntil. */
    public record ReplayContext(String signerDid, String verifierScope, String replayKey, Instant validUntil) {}

    @FunctionalInterface
    public interface ReplayStore {
        CompletionStage<Boolean> consumeOnce(ReplayContext context);
    }

    public static final class ReplayUnavailable extends SecurityException {
        public ReplayUnavailable(Throwable cause) { super("Replay protection unavailable", cause); }
    }

    /** Bounded process-local adapter. Clustered hosts must inject a shared store. */
    public static final class MemoryReplayStore implements ReplayStore {
        private final Clock clock;
        private final int capacity;
        private final Map<String, Instant> seen = new HashMap<>();
        public MemoryReplayStore() { this(Clock.systemUTC(), 10000); }
        public MemoryReplayStore(Clock clock, int capacity) {
            if (clock == null || capacity < 1) throw new IllegalArgumentException("Invalid replay store");
            this.clock = clock; this.capacity = capacity;
        }
        @Override
        public synchronized CompletionStage<Boolean> consumeOnce(ReplayContext context) {
            Instant now = clock.instant();
            seen.entrySet().removeIf(entry -> entry.getValue().isBefore(now));
            if (context.validUntil().isBefore(now) || seen.containsKey(context.replayKey())) {
                return CompletableFuture.completedFuture(false);
            }
            if (seen.size() >= capacity) return CompletableFuture.failedFuture(new SecurityException("Replay store capacity exhausted"));
            seen.put(context.replayKey(), context.validUntil());
            return CompletableFuture.completedFuture(true);
        }
    }

    private static final Pattern SCHEME = Pattern.compile("(?i)^(DIDWba|DID-WBA)\\s+(.+)$");
    private static final Pattern PARAM = Pattern.compile("\\G\\s*([a-zA-Z][a-zA-Z0-9_-]*)\\s*=\\s*\"((?:[^\"\\\\\\r\\n]|\\\\[\"\\\\])*)\"\\s*(?:,\\s*|$)");

    /** Parse once, reject ambiguous duplicates, return only the signed contract. */
    public static Map<String, String> parseHeader(String header) {
        if (header == null || header.length() > 16384 || header.chars().anyMatch(c -> c < 32 || c == 127)) {
            throw new IllegalArgumentException("Invalid authorization header");
        }
        Matcher scheme = SCHEME.matcher(header.trim());
        if (!scheme.matches()) throw new IllegalArgumentException("Unsupported authentication scheme");
        String rest = scheme.group(2);
        Matcher matcher = PARAM.matcher(rest);
        Map<String, String> parsed = new LinkedHashMap<>();
        int end = 0;
        while (end < rest.length()) {
            if (!matcher.find(end) || matcher.start() != end || parsed.size() >= 32) throw new IllegalArgumentException("Invalid authentication parameters");
            String name = matcher.group(1).toLowerCase(Locale.ROOT);
            String value = matcher.group(2).replace("\\\"", "\"").replace("\\\\", "\\");
            if (parsed.putIfAbsent(name, value) != null) throw new IllegalArgumentException("Duplicate authentication parameter");
            end = matcher.end();
        }
        Map<String, String> result = new HashMap<>();
        for (String field : List.of("did", "nonce", "timestamp", "verification_method", "signature")) {
            String value = parsed.get(field);
            if (value == null || value.isEmpty()) throw new IllegalArgumentException("Missing authentication parameter");
            result.put(field, value);
        }
        if (!result.get("did").startsWith("did:wba:") || result.get("did").contains("#")
                || result.get("nonce").length() > 1024 || result.get("nonce").indexOf(0) >= 0) {
            throw new IllegalArgumentException("Invalid authentication identity or nonce");
        }
        String version = parsed.getOrDefault("v", "1.0");
        if (!version.matches("[0-9]+(?:\\.[0-9]+)?")) throw new IllegalArgumentException("Invalid authentication version");
        result.put("version", version);
        return result;
    }

    public static ReplayContext replayContext(Map<String, String> verified, String scope, Policy policy) {
        if (!policy.checkTime() || scope == null || scope.isEmpty() || scope.indexOf(0) >= 0) {
            throw new SecurityException("Full authentication requires real-time policy and trusted scope");
        }
        String did = verified.get("did"), nonce = verified.get("nonce");
        if (did == null || nonce == null || did.indexOf(0) >= 0 || nonce.indexOf(0) >= 0) throw new SecurityException("Invalid replay context");
        String material = String.join("\0", "anp.legacy-auth.replay.v1", scope, did, nonce);
        try {
            String digest = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(material.getBytes(StandardCharsets.UTF_8)));
            return new ReplayContext(did, scope, digest, policy.validateTimestamp(verified.get("timestamp")).plusSeconds(policy.futureSkewSeconds()));
        } catch (java.security.NoSuchAlgorithmException impossible) { throw new IllegalStateException(impossible); }
    }
}
