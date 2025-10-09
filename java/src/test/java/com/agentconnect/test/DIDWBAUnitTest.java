package com.agentconnect.test;

import com.agentconnect.authentication.DIDWbaAuthHeader;
import com.agentconnect.authentication.VerificationMethod;
import com.agentconnect.utils.DiDDocumentTool;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.erdtman.jcs.JsonCanonicalizer;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;

/**
 * @Description
 * @Author yanliqing
 * @Date 2025/6/1 12:13
 */

public class DIDWBAUnitTest {
    private static final ObjectMapper objectMapper = new ObjectMapper();

    @Test
    public void resolveDIDWBADocument() throws ExecutionException, InterruptedException {
        //注意替换成你自己的did
        String did = "did:wba:service.agent-network-protocol.com:wba:user:d606bcc81672bece";
        CompletableFuture<Map<String, Object>> completableFuture = DiDDocumentTool.resolveDIDWBADocument(did);
        Map<String, Object> map = completableFuture.get();
        System.out.println(map);
    }

    @Test
    public void extractAuthHeaderParts() {
        //注意替换成你自己的did和私钥目录
        String didDocumentPath = "/Users/yanliqing/Documents/llm/ANP/anp-fork/AgentConnect/anp/java/src" +
                "/test/resources/did_keys/user_d606bcc81672bece/did.json";
        String privateKeyPath = "/Users/yanliqing/Documents/llm/ANP/anp-fork/AgentConnect/anp/java/src/test" +
                "/resources/did_keys/user_d606bcc81672bece/key-1_private.pem";
        DIDWbaAuthHeader authClient = new DIDWbaAuthHeader(didDocumentPath, privateKeyPath);

        String[] strings = DiDDocumentTool.extractAuthHeaderParts(
                authClient.generateAuthHeader("http://service.agent-network-protocol.com"));
        System.out.println(String.join(",", strings));
    }

    @Test
    public void verifyAuthHeaderSignature() throws IOException {
        //注意替换成你自己的did和私钥目录
        String didDocumentPath = "/Users/yanliqing/Documents/llm/ANP/anp-fork/AgentConnect/anp/java/src" +
                "/test/resources/did_keys/user_d606bcc81672bece/did.json";
        String privateKeyPath = "/Users/yanliqing/Documents/llm/ANP/anp-fork/AgentConnect/anp/java/src/test" +
                "/resources/did_keys/user_d606bcc81672bece/key-1_private.pem";
        //注意替换成你自己的did
        String did = "did:wba:service.agent-network-protocol.com:wba:user:d606bcc81672bece";

        DIDWbaAuthHeader authClient = new DIDWbaAuthHeader(didDocumentPath, privateKeyPath);

        String authHeader = authClient.generateAuthHeader("http://service.agent-network-protocol.com");

        // Extract parts
        String[] parts = DiDDocumentTool.extractAuthHeaderParts(authHeader);
        String hdid = parts[0].split("=")[1].replace("\"","");
        String hnonce = parts[1].split("=")[1].replace("\"","");
        String htimestamp = parts[2].split("=")[1].replace("\"","");
        String hmethodFragment = parts[3].split("=")[1].replace("\"","");
        String signature = parts[4].split("=")[1].replace("\"","");

        // 构建要签名的数据
        Map<String, Object> dataToSign = new HashMap<>();
        dataToSign.put("nonce", hnonce);
        dataToSign.put("timestamp", htimestamp);
        dataToSign.put("service", "http://service.agent-network-protocol.com");
        dataToSign.put("did", hdid);

        String jsonString = objectMapper.writeValueAsString(dataToSign);
        // 使用JCS进行JSON规范化
        JsonCanonicalizer canonicalizer = new JsonCanonicalizer(jsonString);
        String canonicalJson = canonicalizer.getEncodedString();

        Map<String, Object> verificationMethodInfo = DiDDocumentTool.selectAuthenticationMethod(DiDDocumentTool.resolveDIDWBADocumentSync(did));
        Map<String,Object> method = (Map<String, Object>) verificationMethodInfo.get("method");

        VerificationMethod verifier = VerificationMethod.fromDict(method);

        // Verify signature
        boolean isValid = verifier.verifySignature(
                canonicalJson.getBytes(StandardCharsets.UTF_8), signature);

        System.out.println(isValid);
    }

}
