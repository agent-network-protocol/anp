package com.agentconnect.spring;

import com.agentconnect.authentication.DIDWBA;
import com.agentconnect.authentication.LegacyAuthSecurity;
import com.agentconnect.utils.CryptoTool;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import javax.servlet.FilterChain;
import java.security.Signature;
import java.security.interfaces.ECPrivateKey;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.atomic.AtomicInteger;
import static org.junit.jupiter.api.Assertions.*;

/** Servlet objects and resolvers are in-memory; no embedded server is started. */
class DidWbaAuthFilterSecurityTest {
    private record Fixture(Map<String,Object> document,String header,LegacyAuthSecurity.Policy policy) {}
    @SuppressWarnings("unchecked")
    private Fixture fixture() {
        Map<String,Object> bundle=DIDWBA.createDIDWBADocument("identity.example",null,List.of("user","unit"),null);
        Map<String,Object> document=(Map<String,Object>)bundle.get("didDocument");
        String pem=(String)((Map<?,?>)bundle.get("keys")).get("key-1");
        ECPrivateKey key=CryptoTool.loadPrivateKeyFromPem(pem);
        String header=DIDWBA.generateAuthHeader(document,"receiver.example",(bytes,fragment)->{
            try {Signature signature=Signature.getInstance("SHA256withECDSA","BC");signature.initSign(key);signature.update(bytes);return signature.sign();}
            catch(Exception failed){throw new IllegalStateException(failed);}
        },"1.1");
        Instant now=Instant.parse(DIDWBA.extractAuthHeaderParts(header).get("timestamp"));
        return new Fixture(document,header,new LegacyAuthSecurity.Policy(Clock.fixed(now,ZoneOffset.UTC),300,60,true));
    }
    private MockHttpServletRequest request(String header) {
        MockHttpServletRequest request=new MockHttpServletRequest("POST","/rpc");
        request.setScheme("https");request.setServerName("receiver.example");request.setServerPort(443);
        if(header!=null)request.addHeader("Authorization",header);
        return request;
    }
    private DidWbaAuthFilter filter(Fixture fixture,LegacyAuthSecurity.ReplayStore store,AtomicInteger loads) {
        return new DidWbaAuthFilter(List.of(),List.of("receiver.example"),fixture.policy(),store,did->{loads.incrementAndGet();return CompletableFuture.completedFuture(fixture.document());});
    }

    @Test void missingAndInvalidHeadersNeverProjectAnIdentityOrRunTheChain() throws Exception {
        Fixture f=fixture();AtomicInteger loads=new AtomicInteger(),chains=new AtomicInteger();
        var filter=filter(f,new LegacyAuthSecurity.MemoryReplayStore(f.policy().clock(),100),loads);
        for(String header:new String[]{null,"Bearer unverified-marker",f.header().replaceAll("signature=\"[^\"]+\"","signature=\"AA\"")}) {
            var request=request(header);var response=new MockHttpServletResponse();
            request.setAttribute("anp.caller.did",f.document().get("id"));
            request.setAttribute("anp.auth.result",Map.of("did",f.document().get("id"),"verified",true));
            filter.doFilter(request,response,(req,res)->chains.incrementAndGet());
            assertEquals(401,response.getStatus());assertEquals("anonymous",DidWbaAuthFilter.getCallerDid(request));
            assertNull(DidWbaAuthFilter.getAuthResult(request));
        }
        assertEquals(0,chains.get());
    }

    @Test void expiredProofIsRejectedBeforeTheResolver() throws Exception {
        Fixture f=fixture();AtomicInteger loads=new AtomicInteger();
        var expired=new LegacyAuthSecurity.Policy(Clock.fixed(f.policy().clock().instant().plusSeconds(600),ZoneOffset.UTC),300,60,true);
        var filter=new DidWbaAuthFilter(List.of(),List.of("receiver.example"),expired,new LegacyAuthSecurity.MemoryReplayStore(),did->{loads.incrementAndGet();return CompletableFuture.completedFuture(f.document());});
        var response=new MockHttpServletResponse();
        filter.doFilter(request(f.header()),response,(req,res)->fail("Expired proof ran protected handler"));
        assertEquals(401,response.getStatus());assertEquals(0,loads.get());
    }

    @Test void sixFieldVersionedLegacyWorksAndSharedStoreRejectsTheSecondFilter() throws Exception {
        Fixture f=fixture();AtomicInteger loads=new AtomicInteger(),chains=new AtomicInteger();
        var store=new LegacyAuthSecurity.MemoryReplayStore(f.policy().clock(),100);
        FilterChain chain=(req,res)->chains.incrementAndGet();
        var first=request(f.header());var firstResponse=new MockHttpServletResponse();
        filter(f,store,loads).doFilter(first,firstResponse,chain);
        assertEquals(200,firstResponse.getStatus());assertEquals(f.document().get("id"),DidWbaAuthFilter.getCallerDid(first));
        assertEquals(true,DidWbaAuthFilter.getAuthResult(first).get("verified"));
        var second=request(f.header());var secondResponse=new MockHttpServletResponse();
        filter(f,store,loads).doFilter(second,secondResponse,chain);
        assertEquals(401,secondResponse.getStatus());assertEquals(1,chains.get());
        assertEquals("anonymous",DidWbaAuthFilter.getCallerDid(second));
    }

    @Test void storeFailureReturnsUnavailableWithNoAnonymousFallback() throws Exception {
        Fixture f=fixture();var filter=filter(f,context->CompletableFuture.failedFuture(new IllegalStateException("unit offline")),new AtomicInteger());
        var request=request(f.header());var response=new MockHttpServletResponse();
        filter.doFilter(request,response,(req,res)->fail("Store outage ran handler"));
        assertEquals(503,response.getStatus());assertEquals("anonymous",DidWbaAuthFilter.getCallerDid(request));
    }

    @Test @SuppressWarnings("unchecked") void declaredVerificationFragmentMustBeAuthorized() throws Exception {
        Fixture f=fixture();String did=(String)f.document().get("id");
        var methods=new ArrayList<>((List<Map<String,Object>>)f.document().get("verificationMethod"));
        Map<String,Object> alias=new HashMap<>(methods.get(0));alias.put("id",did+"#assertion-only");methods.add(alias);
        f.document().put("verificationMethod",methods);f.document().put("assertionMethod",List.of(did+"#assertion-only"));
        var request=request(f.header().replace("verification_method=\"key-1\"","verification_method=\"assertion-only\""));
        var response=new MockHttpServletResponse();
        filter(f,new LegacyAuthSecurity.MemoryReplayStore(f.policy().clock(),100),new AtomicInteger()).doFilter(request,response,(req,res)->fail("Unauthorized key reached handler"));
        assertEquals(401,response.getStatus());assertEquals("anonymous",DidWbaAuthFilter.getCallerDid(request));
    }

    @Test void explicitPublicPathRemainsAnonymous() throws Exception {
        Fixture f=fixture();var filter=filter(f,new LegacyAuthSecurity.MemoryReplayStore(f.policy().clock(),100),new AtomicInteger());
        var request=new MockHttpServletRequest("GET","/agent/ad.json");var response=new MockHttpServletResponse();
        AtomicInteger chains=new AtomicInteger();filter.doFilter(request,response,(req,res)->chains.incrementAndGet());
        assertEquals(1,chains.get());assertEquals("anonymous",DidWbaAuthFilter.getCallerDid(request));
    }
    @Test void receiverHostAndPortNeedConfigurationNotAForwardedAssertion() throws Exception {
        Fixture f=fixture();AtomicInteger loads=new AtomicInteger();
        var configured=filter(f,new LegacyAuthSecurity.MemoryReplayStore(f.policy().clock(),100),loads);
        for(String host:new String[]{"foreign.example","receiver.example"}) {
            var request=request(f.header());request.setServerName(host);request.setServerPort(8443);
            request.addHeader("X-Forwarded-Host","receiver.example");
            var response=new MockHttpServletResponse();
            configured.doFilter(request,response,(req,res)->fail("Untrusted origin ran handler"));
            assertEquals(401,response.getStatus());
        }
        var unconfigured=new DidWbaAuthFilter(List.of(),List.of(),f.policy(),new LegacyAuthSecurity.MemoryReplayStore(f.policy().clock(),100),did->{loads.incrementAndGet();return CompletableFuture.completedFuture(f.document());});
        var response=new MockHttpServletResponse();
        unconfigured.doFilter(request(f.header()),response,(req,res)->fail("Unconfigured origin ran handler"));
        assertEquals(401,response.getStatus());assertEquals(0,loads.get());
    }

}
