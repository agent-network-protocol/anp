package com.agentconnect.authentication;

import org.apache.hc.client5.http.DnsResolver;
import org.apache.hc.client5.http.classic.methods.HttpUriRequestBase;
import org.apache.hc.client5.http.config.RequestConfig;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManagerBuilder;
import org.apache.hc.client5.http.ssl.DefaultHostnameVerifier;
import org.apache.hc.client5.http.ssl.SSLConnectionSocketFactoryBuilder;
import org.apache.hc.core5.http.ContentType;
import org.apache.hc.core5.http.io.entity.ByteArrayEntity;
import org.apache.hc.core5.ssl.SSLContexts;
import org.apache.hc.core5.util.Timeout;

import java.io.IOException;
import java.net.InetAddress;
import java.net.URI;
import java.net.UnknownHostException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

/** Apache's existing HTTP stack with connection-level checked DNS and TLS. */
public final class PublicHttpTransport {
    public record Response(int status, Map<String, List<String>> headers, byte[] body) {
        public String text() { return new String(body, java.nio.charset.StandardCharsets.UTF_8); }
        public Map<String, String> authenticationHeaders() {
            Map<String, String> result = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
            headers.forEach((name, values) -> {
                if ((name.equalsIgnoreCase("Authentication-Info") || name.equalsIgnoreCase("Authorization")) && values.size() != 1) {
                    throw new SecurityException("Ambiguous authentication response header");
                }
                if (!values.isEmpty()) result.put(name, values.get(0));
            });
            return result;
        }
    }

    @FunctionalInterface
    public interface Transport {
        Response request(URI uri, String method, Map<String, String> headers, byte[] body) throws IOException;
    }

    @FunctionalInterface public interface AddressLookup {
        InetAddress[] resolve(String host) throws UnknownHostException;
    }

    private static final ThreadPoolExecutor IO = new ThreadPoolExecutor(8, 8, 30, TimeUnit.SECONDS,
            new ArrayBlockingQueue<>(32), runnable -> { Thread thread = new Thread(runnable, "anp-public-http"); thread.setDaemon(true); return thread; });
    static { IO.allowCoreThreadTimeOut(true); }
    private static final ThreadPoolExecutor ASYNC = new ThreadPoolExecutor(8,8,30,TimeUnit.SECONDS,
            new ArrayBlockingQueue<>(32),runnable->{Thread thread=new Thread(runnable,"anp-async-api");thread.setDaemon(true);return thread;});
    static { ASYNC.allowCoreThreadTimeOut(true); }
    private final URI trustedBase;
    private final Duration timeout;
    private final AddressLookup addresses;

    public PublicHttpTransport() { this(null, Duration.ofSeconds(10)); }
    public PublicHttpTransport(URI trustedBase, Duration timeout) {
        this(trustedBase,timeout,InetAddress::getAllByName);
    }
    public PublicHttpTransport(URI trustedBase,Duration timeout,AddressLookup addresses) {
        if (timeout == null || timeout.isZero() || timeout.isNegative() || timeout.compareTo(Duration.ofMinutes(5)) > 0) {
            throw new IllegalArgumentException("Invalid public transport timeout");
        }
        if (trustedBase != null) PublicNetworkPolicy.validate(trustedBase, trustedBase);
        if(addresses==null)throw new IllegalArgumentException("Missing address resolver");
        this.trustedBase = trustedBase; this.timeout = timeout; this.addresses=addresses;
    }
    public Transport asTransport() { return this::request; }

    /** Bounded async facades must not grow the shared ForkJoinPool with blocked IO. */
    public static <T> java.util.concurrent.CompletableFuture<T> async(java.util.concurrent.Callable<T> operation,Duration budget) {
        if(budget==null||budget.isNegative()||budget.isZero())return java.util.concurrent.CompletableFuture.failedFuture(new IllegalArgumentException("Invalid async budget"));
        var result=new java.util.concurrent.CompletableFuture<T>();
        final Future<?> task;
        try {ASYNC.purge();task=ASYNC.submit(()->{if(result.isDone())return;try{result.complete(operation.call());}catch(Exception failed){result.completeExceptionally(failed);}});}
        catch(java.util.concurrent.RejectedExecutionException busy){return java.util.concurrent.CompletableFuture.failedFuture(new IOException("ANP async budget exhausted"));}
        result.orTimeout(budget.toMillis(),TimeUnit.MILLISECONDS).whenComplete((value,error)->{if(error!=null)task.cancel(true);});
        return result;
    }

    public Response request(URI uri, String method, Map<String, String> headers, byte[] body) throws IOException {
        PublicNetworkPolicy.validate(uri, trustedBase);
        if (!method.matches("[A-Z]+") || body.length > PublicNetworkPolicy.MAX_BYTES) throw new IOException("Invalid ANP HTTP request");
        HttpUriRequestBase request = new HttpUriRequestBase(method, uri);
        request.setHeader("Accept", "application/json");
        headers.forEach((name, value) -> {
            if (List.of("host", "connection", "content-length", "transfer-encoding").contains(name.toLowerCase(java.util.Locale.ROOT))
                    || name.chars().anyMatch(c -> c <= 32 || c == 127) || value.chars().anyMatch(c -> c < 32 || c == 127)) {
                throw new SecurityException("Invalid or overridden HTTP binding header");
            }
            request.setHeader(name, value);
        });
        if (body.length > 0) request.setEntity(new ByteArrayEntity(body, ContentType.APPLICATION_JSON));
        final Future<Response> future;
        try {
            IO.purge();
            future = IO.submit(() -> execute(request));
        } catch (java.util.concurrent.RejectedExecutionException busy) { throw new IOException("ANP HTTP concurrency budget exhausted"); }
        try { return future.get(timeout.toMillis(), TimeUnit.MILLISECONDS); }
        catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt(); request.cancel(); future.cancel(true); throw new IOException("ANP request interrupted");
        } catch (TimeoutException expired) {
            request.cancel(); future.cancel(true); throw new IOException("ANP request timeout");
        } catch (ExecutionException failed) { throw new IOException("ANP request rejected", failed.getCause()); }
    }

    /** Adapter handed to the actual HTTP connection manager, also unit-injectable. */
    public DnsResolver connectionDnsResolver() {
        return new DnsResolver() {
            @Override public InetAddress[] resolve(String host) throws UnknownHostException {
                InetAddress[] resolved = addresses.resolve(host);
                return trustedBase == null ? PublicNetworkPolicy.checkAddresses(resolved) : resolved;
            }
            @Override public String resolveCanonicalHostname(String host) { return host; }
        };
    }

    private Response execute(HttpUriRequestBase request) throws IOException {
        var manager = PoolingHttpClientConnectionManagerBuilder.create().setDnsResolver(connectionDnsResolver())
                .setSSLSocketFactory(SSLConnectionSocketFactoryBuilder.create()
                        .setSslContext(SSLContexts.createSystemDefault()).setHostnameVerifier(new DefaultHostnameVerifier()).build())
                .setMaxConnTotal(8).setMaxConnPerRoute(8).build();
        try (CloseableHttpClient client = HttpClients.custom().setConnectionManager(manager)
                .disableRedirectHandling().disableAutomaticRetries()
                .setDefaultRequestConfig(RequestConfig.custom().setConnectTimeout(Timeout.ofMilliseconds(timeout.toMillis()))
                        .setConnectionRequestTimeout(Timeout.ofMilliseconds(timeout.toMillis()))
                        .setResponseTimeout(Timeout.ofMilliseconds(timeout.toMillis())).build()).build()) {
            var response = client.execute(request);
            try {
                Map<String, List<String>> result = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
                for (var header : response.getHeaders()) result.computeIfAbsent(header.getName(), ignored -> new ArrayList<>()).add(header.getValue());
                // Do not drain untrusted redirect/error bodies or follow another origin.
                byte[] bytes = response.getCode() >= 200 && response.getCode() < 300 && response.getEntity() != null
                        ? PublicNetworkPolicy.readBounded(response.getEntity().getContent()) : new byte[0];
                return new Response(response.getCode(), result, bytes);
            } finally { request.cancel(); response.close(); }
        }
    }
}
