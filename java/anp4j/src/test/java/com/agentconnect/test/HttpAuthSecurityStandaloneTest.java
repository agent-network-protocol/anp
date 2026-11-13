package com.agentconnect.test;

import com.agentconnect.authentication.LegacyAuthSecurity;
import com.agentconnect.authentication.PublicNetworkPolicy;
import java.io.ByteArrayInputStream;
import java.net.InetAddress;
import java.net.URI;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executors;

/** Pure JDK units: no sockets, DNS queries, provider credentials or test server. */
public final class HttpAuthSecurityStandaloneTest {
    private static final Instant NOW = Instant.parse("2026-11-13T08:00:00Z");
    private static final String HEADER = "DIDWba v=\"1.1\", did=\"did:wba:unit.example:user:alice\", nonce=\"unit\", timestamp=\"2026-11-13T08:00:00Z\", verification_method=\"key-1\", signature=\"public-unit-marker\"";
    private static void check(boolean value) { if (!value) throw new AssertionError("Security unit assertion failed"); }
    private static void rejects(Runnable operation) {
        boolean failed = false;
        try { operation.run(); } catch (RuntimeException expected) { failed = true; }
        check(failed);
    }

    public static void parser() {
        Map<String, String> fields = LegacyAuthSecurity.parseHeader(HEADER);
        check(fields.get("version").equals("1.1"));
        check(fields.get("did").equals("did:wba:unit.example:user:alice"));
        check(LegacyAuthSecurity.parseHeader(HEADER.replace("DIDWba ", "did-wba ")).get("nonce").equals("unit"));
        rejects(() -> LegacyAuthSecurity.parseHeader(HEADER + ", nonce=\"different\""));
        rejects(() -> LegacyAuthSecurity.parseHeader(HEADER + " garbage"));
        rejects(() -> LegacyAuthSecurity.parseHeader(HEADER.replace("nonce=\"unit\", ", "")));
        rejects(() -> LegacyAuthSecurity.parseHeader(HEADER + "\r\nAuthorization: anything"));
    }

    public static void timestamps() {
        var policy = new LegacyAuthSecurity.Policy(Clock.fixed(NOW, ZoneOffset.UTC), 300, 60, true);
        policy.validateTimestamp(NOW.toString());
        policy.validateTimestamp(NOW.minusSeconds(300).toString());
        policy.validateTimestamp(NOW.plusSeconds(60).toString());
        for (String timestamp : List.of("2001-01-01T00:00:00Z", "2049-01-01T00:00:00Z", NOW.minusSeconds(301).toString(), NOW.plusSeconds(61).toString())) {
            rejects(() -> policy.validateTimestamp(timestamp));
        }
        var offline = new LegacyAuthSecurity.Policy(policy.clock(), 300, 60, false);
        offline.validateTimestamp("2001-01-01T00:00:00Z");
        rejects(() -> LegacyAuthSecurity.replayContext(LegacyAuthSecurity.parseHeader(HEADER), "receiver", offline));
    }

    public static void replay() throws Exception {
        MutableClock clock = new MutableClock();
        var policy = new LegacyAuthSecurity.Policy(clock, 300, 60, true);
        var context = LegacyAuthSecurity.replayContext(LegacyAuthSecurity.parseHeader(HEADER), "receiver", policy);
        check(context.replayKey().length() == 64);
        check(context.validUntil().equals(NOW.plusSeconds(360)));
        check(!context.replayKey().equals(LegacyAuthSecurity.replayContext(LegacyAuthSecurity.parseHeader(HEADER), "other", policy).replayKey()));
        var store = new LegacyAuthSecurity.MemoryReplayStore(clock, 1);
        var workers = Executors.newFixedThreadPool(4);
        try {
            List<CompletableFuture<Boolean>> results = new ArrayList<>();
            for (int i = 0; i < 24; i++) results.add(CompletableFuture.supplyAsync(() -> store.consumeOnce(context).toCompletableFuture().join(), workers));
            int accepted = 0;
            for (var result : results) if (result.join()) accepted++;
            check(accepted == 1);
        } finally { workers.shutdownNow(); }
        clock.now = context.validUntil();
        check(!store.consumeOnce(context).toCompletableFuture().join());
        var other = new LegacyAuthSecurity.ReplayContext(context.signerDid(), context.verifierScope(), "other", clock.now.plusSeconds(60));
        rejects(() -> store.consumeOnce(other).toCompletableFuture().join());
        clock.now = clock.now.plusSeconds(1);
        check(store.consumeOnce(other).toCompletableFuture().join());
    }

    public static void addressesAndResources() throws Exception {
        for (byte[] raw : new byte[][]{{127,0,0,1}, {10,0,0,1}, {(byte)169,(byte)254,(byte)169,(byte)254}}) {
            check(!PublicNetworkPolicy.isPublic(InetAddress.getByAddress(raw)));
            try { PublicNetworkPolicy.checkAddresses(new InetAddress[]{InetAddress.getByAddress(new byte[]{8,8,8,8}),InetAddress.getByAddress(raw)}); throw new AssertionError("Mixed DNS accepted"); }
            catch (java.net.UnknownHostException expected) { }
        }
        check(PublicNetworkPolicy.origin(URI.create("https://EXAMPLE.com/a")).equals(PublicNetworkPolicy.origin(URI.create("https://example.com:443/b"))));
        for (String raw : List.of("http://example.com/", "https://localhost/", "https://127.0.0.1/", "https://[::1]/", "https://[::ffff:127.0.0.1]/", "https://user@example.com/", "https://example.com/#x")) rejects(() -> PublicNetworkPolicy.validate(URI.create(raw), null));
        PublicNetworkPolicy.validate(URI.create("http://127.0.0.1/root/did.json"), URI.create("http://127.0.0.1/root"));
        rejects(() -> PublicNetworkPolicy.validate(URI.create("http://127.0.0.2/root/did.json"), URI.create("http://127.0.0.1/root")));
        check(PublicNetworkPolicy.didResource("did:wba:example.com").getPath().equals("/.well-known/did.json"));
        for (String did : List.of("did:wba:user%40example.com:alice", "did:wba:example.com%2fother:user", "did:wba:example.com:..", "did:wba:example.com:%2fetc")) rejects(() -> PublicNetworkPolicy.didResource(did));
        try { PublicNetworkPolicy.readBounded(new ByteArrayInputStream(new byte[PublicNetworkPolicy.MAX_BYTES + 1])); throw new AssertionError("Oversized body accepted"); }
        catch (java.io.IOException expected) { }
    }

    private static final class MutableClock extends Clock {
        private Instant now = NOW;
        @Override public ZoneId getZone() { return ZoneOffset.UTC; }
        @Override public Clock withZone(ZoneId zone) { return this; }
        @Override public Instant instant() { return now; }
    }

    public static void main(String[] args) throws Exception {
        parser(); timestamps(); replay(); addressesAndResources();
        System.out.println("4 standalone security unit groups passed (no network)");
    }
}
