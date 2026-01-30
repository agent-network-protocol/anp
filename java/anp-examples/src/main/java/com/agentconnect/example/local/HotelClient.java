/**
 * @program: anp4java
 * @description: 本地 Hotel Agent 客户端 - 连接本地服务器进行联调测试
 * @author: Ruitao.Zhai
 * @date: 2025-01-29
 */
package com.agentconnect.example.local;

import com.agentconnect.crawler.ANPCrawler;
import com.agentconnect.crawler.CrawlResult;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.Map;

/**
 * 本地 Hotel Agent 客户端 - 用于与本地服务器联调
 */
public class HotelClient {
    
    private static final Logger log = LoggerFactory.getLogger(HotelClient.class);
    private static final ObjectMapper objectMapper = new ObjectMapper();
    
    private static final String LOCAL_AGENT_URL = "http://localhost:8000/hotel/ad.json";
    private static final String LOCAL_RPC_URL = "http://localhost:8000/hotel/rpc";
    
    public static void main(String[] args) {
        try {
            System.out.println();
            System.out.println("=".repeat(60));
            System.out.println("📱 Hotel Agent 客户端 - 本地联调测试");
            System.out.println("=".repeat(60));
            System.out.println();
            
            // 创建 ANPCrawler（本地测试不需要 DID 认证）
            ANPCrawler crawler = new ANPCrawler();
            
            // 1. 获取 Agent 描述
            System.out.println("【步骤 1】获取 Agent 描述");
            System.out.println("URL: " + LOCAL_AGENT_URL);
            System.out.println();
            
            CrawlResult result = crawler.fetchText(LOCAL_AGENT_URL);
            Map<String, Object> agentDesc = result.getAgentDescription();
            
            if (agentDesc == null || agentDesc.isEmpty()) {
                System.out.println("❌ 无法连接到本地服务器！");
                System.out.println("请先运行: mvn exec:java -Dexec.mainClass=\"com.agentconnect.example.local.HotelServer\"");
                return;
            }
            
            System.out.println("✅ 连接成功！");
            System.out.println("Agent 名称: " + agentDesc.get("name"));
            System.out.println("Agent DID: " + agentDesc.get("did"));
            System.out.println();
            
            // 2. 列出可用方法
            System.out.println("【步骤 2】发现接口");
            List<String> tools = crawler.listAvailableTools();
            System.out.println("发现 " + tools.size() + " 个方法:");
            for (String tool : tools) {
                CrawlResult.MethodInfo info = crawler.getToolInterfaceInfo(tool);
                System.out.println("  - " + tool + ": " + (info != null ? info.getDescription() : ""));
            }
            System.out.println();
            
            // 3. 搜索酒店
            System.out.println("【步骤 3】搜索东京酒店");
            Map<String, Object> searchResult = crawler.executeToolCall("searchHotels", 
                Map.of("city", "Tokyo"));
            System.out.println("搜索结果: " + prettyJson(searchResult));
            System.out.println();
            
            // 4. 获取酒店详情
            System.out.println("【步骤 4】获取酒店 H001 详情");
            Map<String, Object> detailResult = crawler.executeToolCall("getHotelDetails",
                Map.of("hotelId", "H001"));
            System.out.println("酒店详情: " + prettyJson(detailResult));
            System.out.println();
            
            // 5. 预订酒店
            System.out.println("【步骤 5】预订酒店");
            Map<String, Object> bookResult = crawler.executeToolCall("bookHotel", Map.of(
                "hotelId", "H001",
                "checkIn", "2025-02-01",
                "checkOut", "2025-02-03",
                "guestName", "张三",
                "guests", 2
            ));
            System.out.println("预订结果: " + prettyJson(bookResult));
            
            // 提取预订 ID
            @SuppressWarnings("unchecked")
            Map<String, Object> rpcResult = (Map<String, Object>) bookResult.get("result");
            @SuppressWarnings("unchecked")
            Map<String, Object> booking = (Map<String, Object>) rpcResult.get("booking");
            String bookingId = (String) booking.get("bookingId");
            System.out.println();
            
            // 6. 查询预订
            System.out.println("【步骤 6】查询预订 " + bookingId);
            Map<String, Object> getBookingResult = crawler.executeToolCall("getBooking",
                Map.of("bookingId", bookingId));
            System.out.println("预订详情: " + prettyJson(getBookingResult));
            System.out.println();
            
            // 7. 取消预订
            System.out.println("【步骤 7】取消预订");
            Map<String, Object> cancelResult = crawler.executeToolCall("cancelBooking", Map.of(
                "bookingId", bookingId,
                "reason", "行程变更"
            ));
            System.out.println("取消结果: " + prettyJson(cancelResult));
            System.out.println();
            
            // 完成
            System.out.println("=".repeat(60));
            System.out.println("✅ 本地联调测试完成！");
            System.out.println("=".repeat(60));
            
        } catch (Exception e) {
            System.err.println("❌ 错误: " + e.getMessage());
            System.err.println();
            System.err.println("请确保本地服务器已启动:");
            System.err.println("mvn exec:java -Dexec.mainClass=\"com.agentconnect.example.local.HotelServer\"");
            e.printStackTrace();
        }
    }
    
    private static String prettyJson(Object obj) {
        try {
            return objectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(obj);
        } catch (Exception e) {
            return obj.toString();
        }
    }
}
