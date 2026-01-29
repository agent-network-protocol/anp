/**
 * @program: anp4java
 * @description: AP2 支付协议概念示例
 * @author: Ruitao.Zhai
 * @date: 2025-01-29
 **/
package com.agentconnect.example.ap2;

import java.util.*;

/**
 * AP2 支付协议概念示例
 * 
 * 本示例演示：
 * 1. 授权链结构 (Cart -> Payment -> Receipts)
 * 2. 授权如何通过哈希相互引用
 * 3. 签名和验证流程
 */
public class AP2ConceptExample {
    
    public static void main(String[] args) {
        System.out.println();
        System.out.println("=".repeat(60));
        System.out.println("AP2 支付协议 - 概念示例");
        System.out.println("=".repeat(60));
        System.out.println();
        
        // 【步骤 1】AP2 协议概述
        System.out.println("【步骤 1】AP2 协议概述");
        System.out.println("-".repeat(40));
        System.out.println();
        System.out.println("AP2 (Agent Payment Protocol) 支持 Agent 之间的安全支付。");
        System.out.println("它使用加密签名的授权链：");
        System.out.println();
        System.out.println("  [CartMandate] --> hash --> [PaymentMandate] --> hash --> [Receipts]");
        System.out.println("       |                           |                          |");
        System.out.println("  由商家签名                  由买家签名                  由商家签名");
        System.out.println();
        
        // 【步骤 2】购物车授权
        System.out.println("【步骤 2】CartMandate (由商家创建)");
        System.out.println("-".repeat(40));
        
        Map<String, Object> cartMandate = createSampleCartMandate();
        System.out.println("CartMandate 结构：");
        System.out.println(prettyPrint(cartMandate));
        System.out.println();
        
        // 【步骤 3】支付授权
        System.out.println("【步骤 3】PaymentMandate (由买家创建)");
        System.out.println("-".repeat(40));
        
        Map<String, Object> paymentMandate = createSamplePaymentMandate();
        System.out.println("PaymentMandate 结构：");
        System.out.println(prettyPrint(paymentMandate));
        System.out.println();
        
        // 【步骤 4】验证流程
        System.out.println("【步骤 4】验证流程");
        System.out.println("-".repeat(40));
        System.out.println();
        System.out.println("1. 商家创建带有支付详情的 CartMandate");
        System.out.println("   - 使用商家的私钥签名");
        System.out.println("   - 计算 cart_hash = hash(cart_mandate_contents)");
        System.out.println();
        System.out.println("2. 买家收到 CartMandate");
        System.out.println("   - 验证商家的签名");
        System.out.println("   - 审查支付详情");
        System.out.println();
        System.out.println("3. 买家创建 PaymentMandate");
        System.out.println("   - 包含 cart_hash 以链接到 CartMandate");
        System.out.println("   - 使用买家的私钥签名");
        System.out.println("   - 计算 pmt_hash = hash(payment_mandate_contents)");
        System.out.println();
        System.out.println("4. 商家验证 PaymentMandate");
        System.out.println("   - 验证买家的签名");
        System.out.println("   - 验证 cart_hash 是否与原始 CartMandate 匹配");
        System.out.println("   - 发起支付处理");
        System.out.println();
        System.out.println("5. 商家开具收据");
        System.out.println("   - PaymentReceipt：支付证明");
        System.out.println("   - FulfillmentReceipt：交付/履约证明");
        System.out.println("   - 两者都包含 pmt_hash 以链接到 PaymentMandate");
        System.out.println();
        
        // 【步骤 5】支持的算法
        System.out.println("【步骤 5】支持的签名算法");
        System.out.println("-".repeat(40));
        System.out.println();
        System.out.println("| 算法      | 描述                          | 用例                 |");
        System.out.println("|-----------|-------------------------------|----------------------|");
        System.out.println("| RS256     | RSA PKCS#1 v1.5 with SHA-256  | 通用用途             |");
        System.out.println("| ES256K    | ECDSA with secp256k1 + SHA-256 | 区块链/加密货币       |");
        System.out.println();
        
        // 【步骤 6】实现状态
        System.out.println("【步骤 6】实现状态");
        System.out.println("-".repeat(40));
        System.out.println();
        System.out.println("Python SDK：提供完整实现");
        System.out.println("  - MerchantAgent: build_cart_mandate, verify_payment_mandate, build_receipts");
        System.out.println("  - ShopperAgent: verify_cart_mandate, build_payment_mandate");
        System.out.println("  - 完整的 RS256 和 ES256K 支持");
        System.out.println();
        System.out.println("Java SDK：仅概念（本示例）");
        System.out.println("  - 可通过 nimbus-jose-jwt 或 jjwt 进行 JWT 签名");
        System.out.println("  - 可通过 MessageDigest 进行哈希计算");
        System.out.println("  - 完整实现需要：");
        System.out.println("    * CartMandate/PaymentMandate 模型");
        System.out.println("    * JWT 签名和验证");
        System.out.println("    * 哈希链验证");
        System.out.println();
        
        // 总结
        System.out.println("=".repeat(60));
        System.out.println("AP2 支付协议 - 概念示例完成");
        System.out.println();
        System.out.println("要点：");
        System.out.println("  - AP2 使用加密授权进行安全支付");
        System.out.println("  - 每个授权都经过签名并通过哈希引用前一个");
        System.out.println("  - 实现 Agent 之间的免信任支付");
        System.out.println("  - Python SDK 中提供了完整的实现");
        System.out.println("=".repeat(60));
    }
    
    /**
     * 创建一个示例 CartMandate 结构。
     */
    private static Map<String, Object> createSampleCartMandate() {
        Map<String, Object> mandate = new LinkedHashMap<>();
        
        // 授权元数据
        mandate.put("cart_mandate_id", "CM-" + System.currentTimeMillis());
        mandate.put("merchant_did", "did:wba:merchant.example.com:shop");
        mandate.put("shopper_did", "did:wba:shopper.example.com:alice");
        
        // 购物车内容
        Map<String, Object> contents = new LinkedHashMap<>();
        contents.put("id", "cart_12345");
        contents.put("user_signature_required", false);
        
        // 支付请求
        Map<String, Object> paymentRequest = new LinkedHashMap<>();
        
        // 方法数据
        Map<String, Object> methodData = new LinkedHashMap<>();
        methodData.put("supported_methods", "QR_CODE");
        
        Map<String, Object> data = new LinkedHashMap<>();
        data.put("channel", "ALIPAY");
        data.put("qr_url", "https://qr.alipay.com/xxx");
        data.put("out_trade_no", "TRD123456");
        methodData.put("data", data);
        
        paymentRequest.put("method_data", Arrays.asList(methodData));
        
        // 支付详情
        Map<String, Object> details = new LinkedHashMap<>();
        details.put("id", "order_12345");
        details.put("displayItems", Arrays.asList(
            Map.of("label", "Product A", "amount", Map.of("currency", "USD", "value", "99.00")),
            Map.of("label", "Shipping", "amount", Map.of("currency", "USD", "value", "5.00"))
        ));
        details.put("total", Map.of(
            "label", "Total",
            "amount", Map.of("currency", "USD", "value", "104.00")
        ));
        
        paymentRequest.put("details", details);
        contents.put("payment_request", paymentRequest);
        
        mandate.put("cart_mandate_contents", contents);
        
        // 商家授权（JWT 占位符）
        mandate.put("merchant_authorization", "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...<signature>");
        
        return mandate;
    }
    
    /**
     * 创建一个示例 PaymentMandate 结构。
     */
    private static Map<String, Object> createSamplePaymentMandate() {
        Map<String, Object> mandate = new LinkedHashMap<>();
        
        // 授权元数据
        mandate.put("payment_mandate_id", "PM-" + System.currentTimeMillis());
        mandate.put("merchant_did", "did:wba:merchant.example.com:shop");
        mandate.put("shopper_did", "did:wba:shopper.example.com:alice");
        
        // 支付授权内容
        Map<String, Object> contents = new LinkedHashMap<>();
        contents.put("id", "payment_12345");
        
        // 通过哈希引用 CartMandate
        contents.put("cart_hash", "sha256:a1b2c3d4e5f6...");
        
        // 支付确认
        contents.put("payment_confirmed", true);
        contents.put("confirmed_at", "2025-01-29T10:00:00Z");
        
        // 选择的支付方式
        contents.put("selected_method", "QR_CODE");
        contents.put("selected_channel", "ALIPAY");
        
        mandate.put("payment_mandate_contents", contents);
        
        // 用户授权（JWT 占位符）
        mandate.put("user_authorization", "eyJhbGciOiJFUzI1NksiLCJ0eXAiOiJKV1QifQ...<signature>");
        
        return mandate;
    }
    
    private static String prettyPrint(Map<String, Object> map) {
        try {
            return new com.fasterxml.jackson.databind.ObjectMapper()
                .writerWithDefaultPrettyPrinter()
                .writeValueAsString(map);
        } catch (Exception e) {
            return map.toString();
        }
    }
}
