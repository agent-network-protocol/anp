/**
 * @program: anp4java
 * @description: 本地 Hotel Agent 定义 - 演示如何使用 @AnpAgent 和 @Interface 注解
 * @author: Ruitao.Zhai
 * @date: 2025-01-29
 */
package com.agentconnect.example.local;

import com.agentconnect.server.annotation.AnpAgent;
import com.agentconnect.server.annotation.Interface;
import com.agentconnect.server.Context;

import java.util.*;

/**
 * 本地 Hotel Agent - 模拟酒店预订服务
 */
@AnpAgent(
    name = "Hotel Booking Agent",
    description = "本地酒店预订 Agent，提供搜索、预订、查询、取消等功能",
    did = "did:wba:localhost:hotel:booking",
    prefix = "/hotel"
)
public class HotelAgent {
    
    // 模拟酒店数据
    private static final List<Map<String, Object>> HOTELS = Arrays.asList(
        createHotel("H001", "东京大酒店", "Tokyo", 350.0, 4.8),
        createHotel("H002", "樱花旅馆", "Tokyo", 150.0, 4.2),
        createHotel("H003", "北京王府酒店", "Beijing", 280.0, 4.5),
        createHotel("H004", "上海中心酒店", "Shanghai", 420.0, 4.9),
        createHotel("H005", "大阪商务酒店", "Osaka", 180.0, 4.0)
    );
    
    // 预订记录
    private final Map<String, Map<String, Object>> bookings = new HashMap<>();
    private int bookingCounter = 1000;
    
    /**
     * 搜索酒店
     */
    @Interface(
        name = "searchHotels",
        description = "按城市搜索酒店",
        inputSchema = "{\"type\":\"object\",\"properties\":{\"city\":{\"type\":\"string\",\"description\":\"城市名称\"},\"minPrice\":{\"type\":\"number\"},\"maxPrice\":{\"type\":\"number\"}},\"required\":[\"city\"]}"
    )
    public Map<String, Object> searchHotels(Map<String, Object> params, Context ctx) {
        String city = (String) params.get("city");
        Double minPrice = params.get("minPrice") != null ? ((Number) params.get("minPrice")).doubleValue() : null;
        Double maxPrice = params.get("maxPrice") != null ? ((Number) params.get("maxPrice")).doubleValue() : null;
        
        List<Map<String, Object>> results = new ArrayList<>();
        for (Map<String, Object> hotel : HOTELS) {
            if (!hotel.get("city").toString().equalsIgnoreCase(city)) continue;
            double price = (Double) hotel.get("pricePerNight");
            if (minPrice != null && price < minPrice) continue;
            if (maxPrice != null && price > maxPrice) continue;
            results.add(hotel);
        }
        
        return Map.of(
            "success", true,
            "city", city,
            "count", results.size(),
            "hotels", results,
            "callerDid", ctx.getCallerDid() != null ? ctx.getCallerDid() : "anonymous"
        );
    }
    
    /**
     * 获取酒店详情
     */
    @Interface(
        name = "getHotelDetails",
        description = "获取酒店详细信息",
        inputSchema = "{\"type\":\"object\",\"properties\":{\"hotelId\":{\"type\":\"string\"}},\"required\":[\"hotelId\"]}"
    )
    public Map<String, Object> getHotelDetails(Map<String, Object> params, Context ctx) {
        String hotelId = (String) params.get("hotelId");
        
        for (Map<String, Object> hotel : HOTELS) {
            if (hotel.get("id").equals(hotelId)) {
                Map<String, Object> details = new HashMap<>(hotel);
                details.put("amenities", Arrays.asList("WiFi", "泳池", "健身房", "餐厅", "停车场"));
                details.put("checkInTime", "15:00");
                details.put("checkOutTime", "11:00");
                details.put("cancellationPolicy", "入住前24小时免费取消");
                return Map.of("success", true, "hotel", details);
            }
        }
        
        return Map.of("success", false, "error", "未找到酒店: " + hotelId);
    }
    
    /**
     * 预订酒店
     */
    @Interface(
        name = "bookHotel",
        description = "预订酒店房间",
        inputSchema = "{\"type\":\"object\",\"properties\":{\"hotelId\":{\"type\":\"string\"},\"checkIn\":{\"type\":\"string\"},\"checkOut\":{\"type\":\"string\"},\"guestName\":{\"type\":\"string\"},\"guests\":{\"type\":\"integer\"}},\"required\":[\"hotelId\",\"checkIn\",\"checkOut\",\"guestName\"]}"
    )
    public Map<String, Object> bookHotel(Map<String, Object> params, Context ctx) {
        String hotelId = (String) params.get("hotelId");
        String checkIn = (String) params.get("checkIn");
        String checkOut = (String) params.get("checkOut");
        String guestName = (String) params.get("guestName");
        int guests = params.get("guests") != null ? ((Number) params.get("guests")).intValue() : 1;
        
        // 查找酒店
        Map<String, Object> hotel = null;
        for (Map<String, Object> h : HOTELS) {
            if (h.get("id").equals(hotelId)) {
                hotel = h;
                break;
            }
        }
        
        if (hotel == null) {
            return Map.of("success", false, "error", "未找到酒店: " + hotelId);
        }
        
        // 创建预订
        String bookingId = "BK" + (++bookingCounter);
        Map<String, Object> booking = new HashMap<>();
        booking.put("bookingId", bookingId);
        booking.put("hotelId", hotelId);
        booking.put("hotelName", hotel.get("name"));
        booking.put("checkIn", checkIn);
        booking.put("checkOut", checkOut);
        booking.put("guests", guests);
        booking.put("guestName", guestName);
        booking.put("pricePerNight", hotel.get("pricePerNight"));
        booking.put("status", "CONFIRMED");
        booking.put("bookedBy", ctx.getCallerDid());
        booking.put("bookedAt", new Date().toString());
        
        bookings.put(bookingId, booking);
        
        return Map.of(
            "success", true,
            "message", "预订成功！",
            "booking", booking
        );
    }
    
    /**
     * 查询预订
     */
    @Interface(
        name = "getBooking",
        description = "查询预订详情",
        inputSchema = "{\"type\":\"object\",\"properties\":{\"bookingId\":{\"type\":\"string\"}},\"required\":[\"bookingId\"]}"
    )
    public Map<String, Object> getBooking(Map<String, Object> params, Context ctx) {
        String bookingId = (String) params.get("bookingId");
        Map<String, Object> booking = bookings.get(bookingId);
        
        if (booking == null) {
            return Map.of("success", false, "error", "未找到预订: " + bookingId);
        }
        
        return Map.of("success", true, "booking", booking);
    }
    
    /**
     * 取消预订
     */
    @Interface(
        name = "cancelBooking",
        description = "取消预订",
        inputSchema = "{\"type\":\"object\",\"properties\":{\"bookingId\":{\"type\":\"string\"},\"reason\":{\"type\":\"string\"}},\"required\":[\"bookingId\"]}"
    )
    public Map<String, Object> cancelBooking(Map<String, Object> params, Context ctx) {
        String bookingId = (String) params.get("bookingId");
        String reason = (String) params.getOrDefault("reason", "用户取消");
        
        Map<String, Object> booking = bookings.get(bookingId);
        if (booking == null) {
            return Map.of("success", false, "error", "未找到预订: " + bookingId);
        }
        
        booking.put("status", "CANCELLED");
        booking.put("cancelledAt", new Date().toString());
        booking.put("cancellationReason", reason);
        
        return Map.of(
            "success", true,
            "message", "预订已取消",
            "booking", booking
        );
    }
    
    private static Map<String, Object> createHotel(String id, String name, String city, 
                                                    double price, double rating) {
        Map<String, Object> hotel = new HashMap<>();
        hotel.put("id", id);
        hotel.put("name", name);
        hotel.put("city", city);
        hotel.put("pricePerNight", price);
        hotel.put("rating", rating);
        return hotel;
    }
}
