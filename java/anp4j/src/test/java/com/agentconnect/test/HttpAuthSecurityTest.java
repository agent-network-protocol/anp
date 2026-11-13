package com.agentconnect.test;

import com.agentconnect.authentication.*;
import com.agentconnect.client.ANPClient;
import com.agentconnect.utils.CryptoTool;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.erdtman.jcs.JsonCanonicalizer;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.Signature;
import java.security.interfaces.ECPrivateKey;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.atomic.AtomicInteger;
import static org.junit.jupiter.api.Assertions.*;

/** All IO is injected or temp-file-only. No test listener or remote endpoint. */
public class HttpAuthSecurityTest {
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final Instant NOW = Instant.parse("2026-11-13T08:00:00Z");
    private static final LegacyAuthSecurity.Policy POLICY = new LegacyAuthSecurity.Policy(Clock.fixed(NOW, ZoneOffset.UTC),300,60,true);
    private record Fixture(Map<String,Object> document, ECPrivateKey key) {}

    @SuppressWarnings("unchecked")
    private Fixture fixture() {
        Map<String,Object> bundle=DIDWBA.createDIDWBADocument("identity.example",null,List.of("user","unit"),null);
        Map<String,Object> doc=(Map<String,Object>)bundle.get("didDocument");
        Map<String,String> keys=(Map<String,String>)bundle.get("keys");
        return new Fixture(doc,CryptoTool.loadPrivateKeyFromPem(keys.get("key-1")));
    }
    private static byte[] canonical(Map<String,Object> value)throws Exception {
        return new JsonCanonicalizer(JSON.writeValueAsString(value)).getEncodedString().getBytes(StandardCharsets.UTF_8);
    }
    private String header(Fixture fixture,String nonce,Instant timestamp)throws Exception {
        String did=(String)fixture.document().get("id");
        Map<String,Object> payload=Map.of("did",did,"nonce",nonce,"timestamp",timestamp.toString(),"aud","receiver.example");
        Signature signer=Signature.getInstance("SHA256withECDSA","BC");
        signer.initSign(fixture.key());signer.update(MessageDigest.getInstance("SHA-256").digest(canonical(payload)));
        String signature=VerificationMethod.fromDict(WbaDocumentBinding.method(fixture.document(),did+"#key-1")).encodeSignature(signer.sign());
        return "DIDWba v=\"1.1\", did=\""+did+"\", nonce=\""+nonce+"\", timestamp=\""+timestamp+"\", verification_method=\"key-1\", signature=\""+signature+"\"";
    }

    @Test void standaloneParser() { HttpAuthSecurityStandaloneTest.parser(); }
    @Test void standaloneTimes() { HttpAuthSecurityStandaloneTest.timestamps(); }
    @Test void standaloneReplay() throws Exception { HttpAuthSecurityStandaloneTest.replay(); }
    @Test void standaloneDestinations() throws Exception { HttpAuthSecurityStandaloneTest.addressesAndResources(); }

    @Test void legacyCryptoTimeAudienceAndAuthorization() throws Exception {
        Fixture f=fixture();String header=header(f,"unit",NOW);
        assertEquals(true,DIDWBA.verifyAuthHeaderSignature(header,f.document(),"receiver.example",POLICY)[0]);
        assertEquals(false,DIDWBA.verifyAuthHeaderSignature(header,f.document(),"other.example",POLICY)[0]);
        assertEquals(false,DIDWBA.verifyAuthHeaderSignature(header(f,"old",Instant.parse("2001-01-01T00:00:00Z")),f.document(),"receiver.example",POLICY)[0]);
        Map<String,Object> unauth=new HashMap<>(f.document());unauth.put("authentication",List.of());
        assertEquals(false,DIDWBA.verifyAuthHeaderSignature(header,unauth,"receiver.example",POLICY)[0]);
        Map<String,Object> wrong=new HashMap<>(f.document());wrong.put("id",((String)wrong.get("id")).toUpperCase(java.util.Locale.ROOT));
        assertEquals(false,DIDWBA.verifyAuthHeaderSignature(header,wrong,"receiver.example",POLICY)[0]);
    }

    @Test void completeAuthConsumesSharedStateAfterCryptoAndClosesOnStoreFailure() throws Exception {
        Fixture f=fixture();String header=header(f,"unit",NOW);
        LegacyAuthSecurity.MemoryReplayStore memory=new LegacyAuthSecurity.MemoryReplayStore(POLICY.clock(),100);
        AtomicInteger calls=new AtomicInteger();
        LegacyAuthSecurity.ReplayStore counted=context->{calls.incrementAndGet();return memory.consumeOnce(context);};
        String invalid=header.replaceAll("signature=\"[^\"]+\"","signature=\"AA\"");
        assertThrows(Exception.class,()->DIDWBA.authenticateAsync(invalid,f.document(),"receiver.example","receiver",POLICY,counted).join());
        assertEquals(0,calls.get());
        var first=DIDWBA.authenticateAsync(header,f.document(),"receiver.example","receiver",POLICY,counted);
        var second=DIDWBA.authenticateAsync(header,f.document(),"receiver.example","receiver",POLICY,counted);
        assertEquals(true,first.join().get("verified"));assertThrows(Exception.class,second::join);
        assertThrows(Exception.class,()->DIDWBA.authenticateAsync(header,f.document(),"receiver.example","receiver",POLICY,context->CompletableFuture.failedFuture(new IllegalStateException("unit store offline"))).join());
    }

    @Test void tokenCacheOriginAndOneShotHeaders(@TempDir Path temp) throws Exception {
        Fixture f=fixture();Path document=temp.resolve("did.json"),key=temp.resolve("key.pem");
        Files.writeString(document,JSON.writeValueAsString(f.document()));Files.writeString(key,CryptoTool.getPemFromPrivateKey(f.key()));
        DIDWbaAuthHeader helper=new DIDWbaAuthHeader(document.toString(),key.toString());
        var first=DIDWBA.extractAuthHeaderParts(helper.getAuthHeader("https://receiver.example/").get("Authorization"));
        var second=DIDWBA.extractAuthHeaderParts(helper.getAuthHeader("https://receiver.example/").get("Authorization"));
        assertNotEquals(first.get("nonce"),second.get("nonce"));
        assertEquals("unit-token==",helper.updateToken("https://receiver.example:8443/",Map.of("Authentication-Info","access_token=\"unit-token==\", token_type=\"Bearer\"")));
        assertEquals("Bearer unit-token==",helper.getAuthHeader("https://receiver.example:8443/path").get("Authorization"));
        assertTrue(helper.getAuthHeader("https://receiver.example/").get("Authorization").startsWith("DIDWba"));
        assertNull(helper.updateToken("http://receiver.example:8443/",Map.of("Authorization","Bearer marker")));
    }

    @Test void discoveryCannotSignOrAdoptTokensAndPrivateUrlsNeverReachTransport() throws Exception {
        AtomicInteger signed=new AtomicInteger(),adopted=new AtomicInteger(),sent=new AtomicInteger();
        DIDWbaAuthHeader helper=new DIDWbaAuthHeader("unused","unused") {
            @Override public Map<String,String> getAuthHeader(String url,boolean force){signed.incrementAndGet();return Map.of("Authorization","DIDWba unit-marker");}
            @Override public String updateToken(String url,Map<String,String> headers){adopted.incrementAndGet();return null;}
        };
        PublicHttpTransport.Transport transport=(uri,method,headers,body)->{sent.incrementAndGet();return new PublicHttpTransport.Response(200,Map.of("Authorization",List.of("Bearer untrusted-marker")),"{}".getBytes(StandardCharsets.UTF_8));};
        ANPClient unsigned=new ANPClient(helper,Duration.ofSeconds(10),Set.of(),null,transport);
        unsigned.fetch("https://public.example/ad.json");assertEquals(0,signed.get());assertEquals(0,adopted.get());
        assertThrows(SecurityException.class,()->unsigned.fetch("https://127.0.0.1/"));assertEquals(1,sent.get());
        ANPClient approved=new ANPClient(helper,Duration.ofSeconds(10),Set.of("https://public.example/"),null,transport);
        approved.fetch("https://public.example/ad.json");assertEquals(1,signed.get());assertEquals(1,adopted.get());
    }

    @Test void ed25519VerifiesContentNotTheSignatureBytes() throws Exception {
        var pair=KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        byte[] x509=pair.getPublic().getEncoded(),raw=java.util.Arrays.copyOfRange(x509,x509.length-32,x509.length);
        Map<String,Object> method=Map.of("type","JsonWebKey2020","publicKeyJwk",Map.of("kty","OKP","crv","Ed25519","x",Base64.getUrlEncoder().withoutPadding().encodeToString(raw)));
        byte[] message="public-unit-message".getBytes(StandardCharsets.UTF_8);
        Signature signer=Signature.getInstance("Ed25519");signer.initSign(pair.getPrivate());signer.update(message);
        String signature=Base64.getUrlEncoder().withoutPadding().encodeToString(signer.sign());
        assertTrue(VerificationMethod.fromDict(method).verifySignature(message,signature));
        assertFalse(VerificationMethod.fromDict(method).verifySignature("wrong".getBytes(StandardCharsets.UTF_8),signature));
    }

    @Test void e1RootFingerprintAndDocumentProofCannotBeReplacedByTheHttpsHost() throws Exception {
        var root=KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        byte[] encoded=root.getPublic().getEncoded(),raw=java.util.Arrays.copyOfRange(encoded,encoded.length-32,encoded.length);
        Map<String,Object> jwk=Map.of("kty","OKP","crv","Ed25519","x",Base64.getUrlEncoder().withoutPadding().encodeToString(raw));
        String fingerprint=Base64.getUrlEncoder().withoutPadding().encodeToString(MessageDigest.getInstance("SHA-256").digest(canonical(jwk)));
        String did="did:wba:identity.example:user:e1_"+fingerprint,keyId=did+"#root";
        Map<String,Object> method=Map.of("id",keyId,"controller",did,"type","JsonWebKey2020","publicKeyJwk",jwk);
        Map<String,Object> doc=new HashMap<>(Map.of("id",did,"verificationMethod",List.of(method),"authentication",List.of(keyId),"assertionMethod",List.of(keyId)));
        Map<String,Object> proof=new HashMap<>(Map.of("type","DataIntegrityProof","cryptosuite","eddsa-jcs-2022","created",NOW.toString(),"verificationMethod",keyId,"proofPurpose","assertionMethod"));
        byte[] input=new byte[64];System.arraycopy(MessageDigest.getInstance("SHA-256").digest(canonical(proof)),0,input,0,32);System.arraycopy(MessageDigest.getInstance("SHA-256").digest(canonical(doc)),0,input,32,32);
        Signature signer=Signature.getInstance("Ed25519");signer.initSign(root.getPrivate());signer.update(input);
        proof.put("proofValue","z"+org.bitcoinj.core.Base58.encode(signer.sign()));doc.put("proof",proof);
        assertTrue(WbaDocumentBinding.validate(doc));
        Map<String,Object> replaced=new HashMap<>(doc);replaced.put("service",List.of());
        assertFalse(WbaDocumentBinding.validate(replaced));
        Map<String,Object> unauthorized=new HashMap<>(doc);unauthorized.put("assertionMethod",List.of());
        assertFalse(WbaDocumentBinding.validate(unauthorized));
        Map<String,Object> wrongIdentity=new HashMap<>(doc);wrongIdentity.put("id",did+"x");
        assertFalse(WbaDocumentBinding.validate(wrongIdentity));
    }
    @Test void checkedDnsIsTheConnectionResolverAndAsyncBudgetIsBounded() throws Exception {
        var publicIp=java.net.InetAddress.getByAddress(new byte[]{8,8,8,8});
        var privateIp=java.net.InetAddress.getByAddress(new byte[]{127,0,0,1});
        var mixed=new PublicHttpTransport(null,Duration.ofSeconds(1),host->new java.net.InetAddress[]{publicIp,privateIp});
        assertThrows(java.net.UnknownHostException.class,()->mixed.connectionDnsResolver().resolve("public.example"));
        var allowed=new PublicHttpTransport(null,Duration.ofSeconds(1),host->new java.net.InetAddress[]{publicIp});
        assertArrayEquals(new java.net.InetAddress[]{publicIp},allowed.connectionDnsResolver().resolve("public.example"));
        assertEquals("done",PublicHttpTransport.async(()->"done",Duration.ofSeconds(1)).get());
        var waiting=PublicHttpTransport.async(()->{new java.util.concurrent.CountDownLatch(1).await();return "never";},Duration.ofMillis(20));
        assertInstanceOf(java.util.concurrent.TimeoutException.class,assertThrows(java.util.concurrent.ExecutionException.class,()->waiting.get(2,java.util.concurrent.TimeUnit.SECONDS)).getCause());
    }

    @Test @SuppressWarnings("unchecked") void frozenLegacyRequestRetainsItsSignedBytes() throws Exception {
        Map<String,Object> frozen=JSON.readValue(Files.readString(Path.of("../../testdata/authentication/legacy_compatibility_v1.json")),Map.class);
        assertEquals(true,DIDWBA.verifyAuthHeaderSignature((String)frozen.get("header"),(Map<String,Object>)frozen.get("document"),(String)frozen.get("domain"),POLICY)[0]);
        assertEquals(false,DIDWBA.verifyAuthHeaderSignature((String)frozen.get("header"),(Map<String,Object>)frozen.get("document"),"foreign.example",POLICY)[0]);
    }

    @Test @SuppressWarnings("unchecked") void k1LegacyRootProofAndFixedWidthEcdsaEncodingRemainCompatible() throws Exception {
        Fixture fixture=fixture();
        String oldDid=(String)fixture.document().get("id");
        Map<String,Object> original=WbaDocumentBinding.method(fixture.document(),oldDid+"#key-1");
        Map<String,Object> publicJwk=new HashMap<>((Map<String,Object>)original.get("publicKeyJwk"));
        publicJwk.remove("kid");
        for(String coordinate:List.of("x","y")){
            byte[] bytes=Base64.getUrlDecoder().decode((String)publicJwk.get(coordinate));
            if(bytes.length==33&&bytes[0]==0)bytes=java.util.Arrays.copyOfRange(bytes,1,33);
            byte[] padded=new byte[32];System.arraycopy(bytes,0,padded,32-bytes.length,bytes.length);
            publicJwk.put(coordinate,Base64.getUrlEncoder().withoutPadding().encodeToString(padded));
        }
        String fingerprint=Base64.getUrlEncoder().withoutPadding().encodeToString(MessageDigest.getInstance("SHA-256").digest(canonical(publicJwk)));
        String did="did:wba:identity.example:user:k1_"+fingerprint,keyId=did+"#root";
        Map<String,Object> method=new HashMap<>(original);method.put("id",keyId);method.put("controller",did);
        Map<String,Object> document=new HashMap<>(Map.of("id",did,"authentication",List.of(keyId),"verificationMethod",List.of(method)));
        Map<String,Object> proof=new HashMap<>(Map.of("type","EcdsaSecp256k1Signature2019","created",NOW.toString(),"verificationMethod",keyId,"proofPurpose","authentication"));
        byte[] input=new byte[64];System.arraycopy(MessageDigest.getInstance("SHA-256").digest(canonical(proof)),0,input,0,32);System.arraycopy(MessageDigest.getInstance("SHA-256").digest(canonical(document)),0,input,32,32);
        Signature signer=Signature.getInstance("SHA256withECDSA","BC");signer.initSign(fixture.key());signer.update(input);
        proof.put("proofValue",VerificationMethod.fromDict(method).encodeSignature(signer.sign()));document.put("proof",proof);
        assertTrue(WbaDocumentBinding.validate(document));
        Map<String,Object> changed=new HashMap<>(document);changed.put("service",List.of());assertFalse(WbaDocumentBinding.validate(changed));
        byte[] shortScalars=new org.bouncycastle.asn1.DERSequence(new org.bouncycastle.asn1.ASN1Encodable[]{new org.bouncycastle.asn1.ASN1Integer(java.math.BigInteger.ONE),new org.bouncycastle.asn1.ASN1Integer(java.math.BigInteger.TWO)}).getEncoded();
        byte[] encoded=Base64.getUrlDecoder().decode(VerificationMethod.fromDict(method).encodeSignature(shortScalars));
        assertEquals(64,encoded.length);assertEquals(1,encoded[31]);assertEquals(2,encoded[63]);
    }

    @Test void ipv6CacheOriginsAreCanonicalWithoutNetworkResolution() {
        assertEquals("https://[2001:4860::8888]:443",PublicNetworkPolicy.origin(URI.create("https://[2001:4860:0000:0000:0000:0000:0000:8888]/")));
        assertThrows(IllegalArgumentException.class,()->PublicNetworkPolicy.origin(URI.create("https://[::ffff:8.8.8.8]/")));
    }

    @Test void approvedOriginWithMissingCredentialProviderCannotFallBackToAnonymous() {
        AtomicInteger sent=new AtomicInteger();
        PublicHttpTransport.Transport transport=(uri,method,headers,body)->{sent.incrementAndGet();return new PublicHttpTransport.Response(200,Map.of(),"{}".getBytes(StandardCharsets.UTF_8));};
        ANPClient client=new ANPClient(null,Duration.ofSeconds(1),Set.of("https://public.example"),null,transport);
        assertThrows(SecurityException.class,()->client.fetch("https://public.example/ad.json"));
        assertEquals(0,sent.get());
    }

    @Test void trustedTestOverrideCannotEscapeItsConfiguredPath() {
        URI base=URI.create("http://127.0.0.1:9891/api");
        PublicNetworkPolicy.validate(URI.create("http://127.0.0.1:9891/api/did%3Awba%3Aidentity.example%253A8443"),base);
        for(String path:List.of("/api/../secret","/api/%2e%2e/secret","/api/%252e%252e/secret","/api/%2e%2e%5csecret","/api-other/secret")) {
            assertThrows(SecurityException.class,()->PublicNetworkPolicy.validate(URI.create("http://127.0.0.1:9891"+path),base));
        }
    }

}
