/**
 * @program: anp4java
 * @description: DID-WBA 示例 - 创建 DID 文档
 * @author: Ruitao.Zhai
 * @date: 2025-01-27
 **/
package com.agentconnect.example.didwba;

import com.agentconnect.utils.CryptoTool;
import com.agentconnect.utils.DIDGenerator;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;

/**
 * 创建 DID 文档示例
 * 
 * 演示功能：
 * 1. 生成 EC 密钥对 (secp256r1)
 * 2. 创建 DID 文档
 * 3. 签名 DID 文档
 * 4. 保存生成的文件
 * 
 * 运行方式：
 *   mvn exec:java -pl anp-examples -Dexec.mainClass="com.agentconnect.example.didwba.CreateDIDDocument"
 */
public class CreateDIDDocument {
    
    private static final ObjectMapper objectMapper = new ObjectMapper();
    
    public static void main(String[] args) {
        try {
            System.out.println();
            System.out.println("=".repeat(60));
            System.out.println("DID 文档创建示例");
            System.out.println("=".repeat(60));
            System.out.println();
            
            // 配置
            String hostname = "demo.agent-network";
            String serviceEndpoint = "https://" + hostname + "/agents/demo";
            
            // 创建输出目录
            Path outputDir = Paths.get("anp-examples/generated/didwba");
            Files.createDirectories(outputDir);
            
            System.out.println("【步骤 1】生成密钥对...");
            
            // 生成 DID 和文档
            Object[] didResult = DIDGenerator.didGenerate(serviceEndpoint, null, hostname, "");
            
            ECPrivateKey privateKey = (ECPrivateKey) didResult[0];
            ECPublicKey publicKey = (ECPublicKey) didResult[1];
            String did = (String) didResult[2];
            String didDocumentJson = (String) didResult[3];
            
            System.out.println("  ✓ 密钥对生成成功");
            System.out.println();
            
            System.out.println("【步骤 2】创建 DID 文档...");
            System.out.println("  DID: " + did);
            System.out.println();
            
            // 保存 DID 文档
            Path didPath = outputDir.resolve("did.json");
            Files.writeString(didPath, didDocumentJson);
            System.out.println("【步骤 3】保存文件...");
            System.out.println("  DID 文档: " + didPath);
            
            // 保存私钥
            String privateKeyPem = CryptoTool.getPemFromPrivateKey(privateKey);
            Path privateKeyPath = outputDir.resolve("key-1_private.pem");
            Files.writeString(privateKeyPath, privateKeyPem);
            System.out.println("  私钥: " + privateKeyPath);
            
            // 保存公钥
            String publicKeyHex = CryptoTool.getHexFromPublicKey(publicKey);
            Path publicKeyPath = outputDir.resolve("key-1_public.txt");
            Files.writeString(publicKeyPath, publicKeyHex);
            System.out.println("  公钥: " + publicKeyPath);
            
            System.out.println();
            System.out.println("=".repeat(60));
            System.out.println("✅ DID 文档创建成功！");
            System.out.println();
            System.out.println("生成的 DID: " + did);
            System.out.println("输出目录: " + outputDir.toAbsolutePath());
            System.out.println("=".repeat(60));
            
        } catch (Exception e) {
            System.err.println("❌ 创建 DID 文档失败: " + e.getMessage());
            e.printStackTrace();
        }
    }
}
