/**
 * @program: anp4java
 * @description: 协议协商概念示例
 * @author: Ruitao.Zhai
 * @date: 2025-01-29
 **/
package com.agentconnect.example.negotiation;

import java.util.*;

/**
 * 协议协商概念示例
 * 
 * 本示例演示：
 * 1. 如何定义接口需求
 * 2. 协商后的接口可能是什么样子的
 * 3. 如何使用协商后的接口
 * 
 * 注意：完整的协商需要：
 * - WebSocket 连接
 * - LLM 集成用于生成提案
 * - 代码生成能力
 */
public class NegotiationConceptExample {
    
    public static void main(String[] args) {
        System.out.println();
        System.out.println("=".repeat(60));
        System.out.println("协议协商 - 概念示例");
        System.out.println("=".repeat(60));
        System.out.println();
        
        // 【步骤 1】定义接口需求（从 Alice 的角度）
        System.out.println("【步骤 1】定义接口需求");
        System.out.println("-".repeat(40));
        
        String requirement = 
            "设计一个用于检索用户教育经历的 API 接口。\n" +
            "- API 应支持检索单个用户的教育经历\n" +
            "- 教育经历应包括：学校名称、专业、学位、成就、开始时间、结束时间\n" +
            "- 必须支持错误处理和参数验证";
        
        String inputDescription = 
            "输入参数应包括：\n" +
            "- user_id：用户 ID（字符串）\n" +
            "- include_details：是否包含详细信息（布尔值，可选）";
        
        String outputDescription = 
            "输出应包括：\n" +
            "- 教育经历列表，每个包含：\n" +
            "  * institution：学校名称\n" +
            "  * major：专业\n" +
            "  * degree：学位（学士/硕士/博士）\n" +
            "  * achievements：成就\n" +
            "  * start_date：开始时间（YYYY-MM-DD）\n" +
            "  * end_date：结束时间（YYYY-MM-DD）\n" +
            "- 支持分页和错误消息返回";
        
        System.out.println("需求：");
        System.out.println(requirement);
        System.out.println();
        System.out.println("输入描述：");
        System.out.println(inputDescription);
        System.out.println();
        System.out.println("输出描述：");
        System.out.println(outputDescription);
        System.out.println();
        
        // 【步骤 2】展示协商后的接口样子
        System.out.println("【步骤 2】协商后的接口（OpenAI Tool 格式）");
        System.out.println("-".repeat(40));
        
        Map<String, Object> negotiatedInterface = createNegotiatedInterface();
        System.out.println("协商后，商定的接口将是：");
        System.out.println(prettyPrint(negotiatedInterface));
        System.out.println();
        
        // 【步骤 3】展示如何使用协商后的接口
        System.out.println("【步骤 3】使用协商后的接口");
        System.out.println("-".repeat(40));
        
        System.out.println("一旦协商完成，两个 Agent 就可以进行通信：");
        System.out.println();
        System.out.println("// Alice (请求者) 端：");
        System.out.println("Map<String, Object> request = Map.of(");
        System.out.println("    \"user_id\", \"alice123\",");
        System.out.println("    \"include_details\", true");
        System.out.println(");");
        System.out.println("Object response = requesterSession.sendRequest(request);");
        System.out.println();
        System.out.println("// Bob (响应者) 端：");
        System.out.println("@Override");
        System.out.println("public Object handleRequest(Map<String, Object> params) {");
        System.out.println("    String userId = (String) params.get(\"user_id\");");
        System.out.println("    Boolean includeDetails = (Boolean) params.get(\"include_details\");");
        System.out.println("    return fetchEducationHistory(userId, includeDetails);");
        System.out.println("}");
        System.out.println();
        
        // 【步骤 4】实现路线图
        System.out.println("【步骤 4】实现路线图");
        System.out.println("-".repeat(40));
        
        System.out.println("要在 Java 中实现完整的协商，您需要：");
        System.out.println();
        System.out.println("1. WebSocket 客户端/服务器（Java-WebSocket 或 Spring WebSocket）");
        System.out.println("   - 用于实时双向通信");
        System.out.println();
        System.out.println("2. LLM 集成（OpenAI Java SDK 或类似）");
        System.out.println("   - 用于生成接口提案");
        System.out.println("   - 用于审查和批准提案");
        System.out.println();
        System.out.println("3. 代码生成");
        System.out.println("   - 根据协商后的 Schema 生成 Java 接口");
        System.out.println("   - 生成实现存根");
        System.out.println();
        System.out.println("4. 协议状态机");
        System.out.println("   - 跟踪协商阶段");
        System.out.println("   - 处理超时和重试");
        System.out.println();
        
        // 总结
        System.out.println("=".repeat(60));
        System.out.println("协议协商 - 概念示例完成");
        System.out.println();
        System.out.println("要点：");
        System.out.println("  - 协商允许 Agent 动态就接口达成一致");
        System.out.println("  - 不需要预先定义的 API 合约");
        System.out.println("  - LLM 生成并验证接口提案");
        System.out.println("  - Python SDK 中提供了完整的实现");
        System.out.println("=".repeat(60));
    }
    
    /**
     * 创建一个 OpenAI Tool 格式的示例协商接口。
     */
    private static Map<String, Object> createNegotiatedInterface() {
        Map<String, Object> tool = new LinkedHashMap<>();
        tool.put("type", "function");
        
        Map<String, Object> function = new LinkedHashMap<>();
        function.put("name", "get_education_history");
        function.put("description", "Retrieve user's education history with optional details");
        
        Map<String, Object> parameters = new LinkedHashMap<>();
        parameters.put("type", "object");
        
        Map<String, Object> properties = new LinkedHashMap<>();
        
        Map<String, Object> userId = new LinkedHashMap<>();
        userId.put("type", "string");
        userId.put("description", "Unique identifier of the user");
        properties.put("user_id", userId);
        
        Map<String, Object> includeDetails = new LinkedHashMap<>();
        includeDetails.put("type", "boolean");
        includeDetails.put("description", "Flag to include detailed information");
        includeDetails.put("default", false);
        properties.put("include_details", includeDetails);
        
        Map<String, Object> page = new LinkedHashMap<>();
        page.put("type", "integer");
        page.put("description", "Page number for pagination");
        page.put("minimum", 1);
        page.put("default", 1);
        properties.put("page", page);
        
        parameters.put("properties", properties);
        parameters.put("required", Arrays.asList("user_id"));
        
        function.put("parameters", parameters);
        
        // Return schema
        Map<String, Object> returns = new LinkedHashMap<>();
        returns.put("type", "object");
        
        Map<String, Object> returnProps = new LinkedHashMap<>();
        
        Map<String, Object> code = new LinkedHashMap<>();
        code.put("type", "integer");
        code.put("description", "HTTP status code");
        returnProps.put("code", code);
        
        Map<String, Object> educationHistory = new LinkedHashMap<>();
        educationHistory.put("type", "array");
        educationHistory.put("description", "Array of education records");
        
        Map<String, Object> historyItem = new LinkedHashMap<>();
        historyItem.put("type", "object");
        Map<String, Object> historyProps = new LinkedHashMap<>();
        historyProps.put("institution", Map.of("type", "string"));
        historyProps.put("major", Map.of("type", "string"));
        historyProps.put("degree", Map.of("type", "string", "enum", Arrays.asList("Bachelor", "Master", "Doctorate")));
        historyProps.put("start_date", Map.of("type", "string", "format", "date"));
        historyProps.put("end_date", Map.of("type", "string", "format", "date"));
        historyItem.put("properties", historyProps);
        educationHistory.put("items", historyItem);
        returnProps.put("education_history", educationHistory);
        
        returns.put("properties", returnProps);
        function.put("returns", returns);
        
        tool.put("function", function);
        
        return tool;
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
