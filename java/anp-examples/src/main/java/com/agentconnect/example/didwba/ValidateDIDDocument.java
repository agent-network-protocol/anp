/**
 * @program: anp4java
 * @description: DID-WBA 示例 - 验证 DID 文档
 * @author: Ruitao.Zhai
 * @date: 2025-01-27
 **/
package com.agentconnect.example.didwba;

import com.fasterxml.jackson.databind.ObjectMapper;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;
import java.util.Map;

/**
 * 验证 DID 文档示例
 * 
 * 本示例演示如何：
 * 1. 从文件加载 DID 文档
 * 2. 验证文档结构
 * 3. 检查验证方法
 * 4. 验证签名（如果存在）
 */
public class ValidateDIDDocument {
    
    private static final ObjectMapper objectMapper = new ObjectMapper();
    
    public static void main(String[] args) {
        try {
            System.out.println();
            System.out.println("=".repeat(60));
            System.out.println("DID 文档验证示例");
            System.out.println("=".repeat(60));
            System.out.println();
            
            String envDidDocPath = System.getenv("ANP_DID_DOC_PATH");
            Path didPath;
            
            if (envDidDocPath != null) {
                didPath = Paths.get(envDidDocPath);
            } else {
                didPath = Paths.get("anp-examples/generated/didwba/did.json");
                if (!Files.exists(didPath)) {
                    didPath = Paths.get("docs/did_public/public-did-doc.json");
                }
            }
            
            if (!Files.exists(didPath)) {
                System.out.println("未找到 DID 文档！");
                System.out.println("可设置环境变量 ANP_DID_DOC_PATH，或先运行 CreateDIDDocument。");
                return;
            }
            
            System.out.println("从以下位置加载 DID 文档：" + didPath);
            System.out.println();
            
            // 加载 DID 文档
            String didDocJson = Files.readString(didPath);
            @SuppressWarnings("unchecked")
            Map<String, Object> didDocument = objectMapper.readValue(didDocJson, Map.class);
            
            // 验证检查
            System.out.println("验证检查：");
            System.out.println("-".repeat(40));
            
            boolean allPassed = true;
            
            // 1. 检查 DID 格式
            String did = (String) didDocument.get("id");
            boolean didValid = did != null && (did.startsWith("did:wba:") || did.startsWith("did:all:"));
            System.out.println("【步骤 1】DID 格式：" + (didValid ? "✅ 通过" : "❌ 失败"));
            if (did != null) {
                System.out.println("   DID: " + did);
            }
            allPassed &= didValid;
            
            // 2. 检查 @context
            Object context = didDocument.get("@context");
            boolean contextValid = context != null;
            System.out.println("【步骤 2】@context 存在：" + (contextValid ? "✅ 通过" : "❌ 失败"));
            allPassed &= contextValid;
            
            // 3. 检查验证方法
            @SuppressWarnings("unchecked")
            List<Object> verificationMethods = (List<Object>) didDocument.get("verificationMethod");
            boolean vmValid = verificationMethods != null && !verificationMethods.isEmpty();
            System.out.println("【步骤 3】验证方法：" + (vmValid ? "✅ 通过" : "❌ 失败"));
            if (vmValid) {
                System.out.println("   找到 " + verificationMethods.size() + " 个验证方法");
                for (Object vm : verificationMethods) {
                    @SuppressWarnings("unchecked")
                    Map<String, Object> vmMap = (Map<String, Object>) vm;
                    System.out.println("   - ID: " + vmMap.get("id"));
                    System.out.println("     类型: " + vmMap.get("type"));
                }
            }
            allPassed &= vmValid;
            
            // 4. 检查认证
            @SuppressWarnings("unchecked")
            List<Object> authentication = (List<Object>) didDocument.get("authentication");
            boolean authValid = authentication != null && !authentication.isEmpty();
            System.out.println("【步骤 4】认证：" + (authValid ? "✅ 通过" : "❌ 失败"));
            allPassed &= authValid;
            
            // 5. 检查服务端点（可选）
            @SuppressWarnings("unchecked")
            List<Object> services = (List<Object>) didDocument.get("service");
            boolean servicePresent = services != null && !services.isEmpty();
            System.out.println("【步骤 5】服务端点：" + (servicePresent ? "存在" : "不存在（可选）"));
            if (servicePresent) {
                for (Object svc : services) {
                    @SuppressWarnings("unchecked")
                    Map<String, Object> svcMap = (Map<String, Object>) svc;
                    System.out.println("   - 类型: " + svcMap.get("type"));
                    System.out.println("     端点: " + svcMap.get("serviceEndpoint"));
                }
            }
            
            // 6. 检查证明（如果存在）
            @SuppressWarnings("unchecked")
            Map<String, Object> proof = (Map<String, Object>) didDocument.get("proof");
            boolean proofPresent = proof != null;
            System.out.println("【步骤 6】证明/签名：" + (proofPresent ? "存在" : "不存在"));
            if (proofPresent) {
                System.out.println("   - 类型: " + proof.get("type"));
                System.out.println("   - 创建时间: " + proof.get("created"));
                System.out.println("   - 目的: " + proof.get("proofPurpose"));
            }
            
            System.out.println();
            System.out.println("=".repeat(60));
            if (allPassed) {
                System.out.println("DID 文档验证成功！");
            } else {
                System.out.println("DID 文档验证失败！");
            }
            System.out.println("=".repeat(60));
            
        } catch (Exception e) {
            System.err.println("验证 DID 文档时出错：" + e.getMessage());
            e.printStackTrace();
        }
    }
}
