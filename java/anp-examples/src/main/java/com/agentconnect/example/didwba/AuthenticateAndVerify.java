/**
 * @program: anp4java
 * @description: DID-WBA 示例 - 认证和验证
 * @author: Ruitao.Zhai
 * @date: 2025-01-28
 **/
package com.agentconnect.example.didwba;

import com.agentconnect.authentication.DIDWbaAuthHeader;
import com.agentconnect.utils.CryptoTool;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Map;

/**
 * 认证和验证示例
 * 
 * 本示例演示完整的 DID-WBA 认证流程：
 * 1. 客户端使用私钥生成 DID 认证头
 * 2. 服务端验证认证头并颁发 Bearer 令牌
 * 3. 客户端在后续请求中使用 Bearer 令牌
 */
public class AuthenticateAndVerify {
    
    private static final ObjectMapper objectMapper = new ObjectMapper();
    
    public static void main(String[] args) {
        try {
            System.out.println();
            System.out.println("=".repeat(60));
            System.out.println("DID-WBA 认证流程示例");
            System.out.println("=".repeat(60));
            System.out.println();
            
            String envDidDocPath = System.getenv("ANP_DID_DOC_PATH");
            String envPrivateKeyPath = System.getenv("ANP_PRIVATE_KEY_PATH");
            
            Path didDocPath;
            Path privateKeyPath;
            
            if (envDidDocPath != null && envPrivateKeyPath != null) {
                didDocPath = Paths.get(envDidDocPath);
                privateKeyPath = Paths.get(envPrivateKeyPath);
            } else {
                didDocPath = Paths.get("anp-examples/generated/didwba/did.json");
                privateKeyPath = Paths.get("anp-examples/generated/didwba/key-1_private.pem");
                
                if (!Files.exists(didDocPath)) {
                    didDocPath = Paths.get("docs/did_public/public-did-doc.json");
                    privateKeyPath = Paths.get("docs/did_public/public-private-key.pem");
                }
            }
            
            // 检查文件是否存在
            if (!Files.exists(didDocPath) || !Files.exists(privateKeyPath)) {
                System.out.println("未找到 DID 凭据！");
                System.out.println("请先运行 CreateDIDDocument 生成 DID 文档和密钥对。");
                System.out.println();
                System.out.println("运行命令：");
                System.out.println("  mvn exec:java -pl anp-examples -Dexec.mainClass=\"com.agentconnect.example.didwba.CreateDIDDocument\"");
                return;
            }
            
            // 加载 DID 文档以获取 DID
            String didDocJson = Files.readString(didDocPath);
            @SuppressWarnings("unchecked")
            Map<String, Object> didDocument = objectMapper.readValue(didDocJson, Map.class);
            String did = (String) didDocument.get("id");
            
            System.out.println("客户端 DID：" + did);
            System.out.println("DID 文档：" + didDocPath);
            System.out.println("私钥：" + privateKeyPath);
            System.out.println();
            
            // 【步骤 1】创建 DID 认证头
            System.out.println("【步骤 1】生成 DID 认证头");
            System.out.println("-".repeat(40));
            
            DIDWbaAuthHeader authClient = new DIDWbaAuthHeader(
                didDocPath.toString(),
                privateKeyPath.toString()
            );
            
            String targetDomain = "example.com";
            String authHeader = authClient.generateAuthHeader(targetDomain);
            
            System.out.println("目标域名：" + targetDomain);
            System.out.println("生成的认证头：" + authHeader.substring(0, Math.min(50, authHeader.length())) + "...");
            System.out.println();
            
            // 【步骤 2】获取请求的 HTTP 头
            System.out.println("【步骤 2】获取请求的 HTTP 头");
            System.out.println("-".repeat(40));
            
            String targetUrl = "https://" + targetDomain + "/api/resource";
            Map<String, String> headers = authClient.getAuthHeader(targetUrl);
            
            System.out.println("请求 URL：" + targetUrl);
            System.out.println("Authorization 头：" + 
                headers.get("Authorization").substring(0, Math.min(50, headers.get("Authorization").length())) + "...");
            System.out.println();
            
            // 【步骤 3】模拟服务端验证（概念性）
            System.out.println("【步骤 3】服务端验证（概念性）");
            System.out.println("-".repeat(40));
            System.out.println("在真实场景中，服务器将：");
            System.out.println("  1. 从 Authorization 头中提取 DID");
            System.out.println("  2. 解析 DID 文档（从 .well-known 或 DID 解析器）");
            System.out.println("  3. 使用 DID 文档中的公钥验证签名");
            System.out.println("  4. 如果验证成功，颁发 Bearer 令牌");
            System.out.println();
            
            // 【步骤 4】模拟令牌更新
            System.out.println("【步骤 4】令牌更新（模拟）");
            System.out.println("-".repeat(40));
            
            // 模拟从服务器接收 Bearer 令牌
            String simulatedBearerToken = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.Signature";
            Map<String, String> responseHeaders = Map.of(
                "authorization", "Bearer " + simulatedBearerToken
            );
            
            String updatedToken = authClient.updateToken(targetUrl, responseHeaders);
            System.out.println("收到服务器的 Bearer 令牌");
            System.out.println("已存储域名的令牌：" + targetDomain);
            System.out.println();
            
            // 【步骤 5】后续请求使用 Bearer 令牌
            System.out.println("【步骤 5】后续请求（使用 Bearer 令牌）");
            System.out.println("-".repeat(40));
            
            Map<String, String> subsequentHeaders = authClient.getAuthHeader(targetUrl);
            System.out.println("头部类型：" + (subsequentHeaders.get("Authorization").startsWith("Bearer ") ? "Bearer 令牌" : "DID 认证"));
            System.out.println();
            
            // 总结
            System.out.println("=".repeat(60));
            System.out.println("认证流程完成！");
            System.out.println();
            System.out.println("总结：");
            System.out.println("  - DID 认证头生成成功");
            System.out.println("  - Bearer 令牌已接收并存储");
            System.out.println("  - 后续请求将自动使用 Bearer 令牌");
            System.out.println("=".repeat(60));
            
        } catch (Exception e) {
            System.err.println("认证流程出错：" + e.getMessage());
            e.printStackTrace();
        }
    }
}
