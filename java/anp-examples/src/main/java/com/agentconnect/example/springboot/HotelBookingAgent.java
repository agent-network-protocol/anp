/**
 * @program: anp4java
 * @description: Hotel Booking Agent - Spring Boot 示例，与 Python FastANP 对齐
 * @author: Ruitao.Zhai
 * @date: 2025-01-20
 **/
package com.agentconnect.example.springboot;

import com.agentconnect.server.Context;
import com.agentconnect.server.annotation.AnpAgent;
import com.agentconnect.server.annotation.Interface;
import org.springframework.stereotype.Component;

import java.util.*;

@Component
@AnpAgent(
    name = "Hotel Booking Agent",
    description = "Intelligent hotel booking agent with room search and reservation capabilities",
    did = "did:wba:hotel.example.com:service:booking",
    prefix = "/hotel"
)
public class HotelBookingAgent {
    
    private static final List<Map<String, Object>> HOTELS = Arrays.asList(
        createHotel("H001", "Grand Hotel Tokyo", "Tokyo", 350.0, 4.8),
        createHotel("H002", "Sakura Inn", "Tokyo", 150.0, 4.2),
        createHotel("H003", "Beijing Palace Hotel", "Beijing", 280.0, 4.5),
        createHotel("H004", "Shanghai Tower Hotel", "Shanghai", 420.0, 4.9),
        createHotel("H005", "Osaka Business Hotel", "Osaka", 180.0, 4.0)
    );
    
    private final Map<String, Map<String, Object>> bookings = new HashMap<>();
    private int bookingCounter = 1000;
    
    @Interface(
        name = "searchHotels",
        description = "Search for available hotels by city"
    )
    public Map<String, Object> searchHotels(Map<String, Object> params, Context ctx) {
        String city = (String) params.get("city");
        
        List<Map<String, Object>> results = new ArrayList<>();
        for (Map<String, Object> hotel : HOTELS) {
            if (hotel.get("city").toString().equalsIgnoreCase(city)) {
                results.add(hotel);
            }
        }
        
        return Map.of(
            "success", true,
            "city", city,
            "count", results.size(),
            "hotels", results,
            "searchedBy", ctx.getDid()
        );
    }
    
    @Interface(
        name = "getHotelDetails",
        description = "Get detailed information about a specific hotel"
    )
    public Map<String, Object> getHotelDetails(Map<String, Object> params, Context ctx) {
        String hotelId = (String) params.get("hotelId");
        
        for (Map<String, Object> hotel : HOTELS) {
            if (hotel.get("id").equals(hotelId)) {
                Map<String, Object> details = new HashMap<>(hotel);
                details.put("amenities", Arrays.asList("WiFi", "Pool", "Gym", "Restaurant"));
                details.put("checkInTime", "15:00");
                details.put("checkOutTime", "11:00");
                return Map.of("success", true, "hotel", details);
            }
        }
        
        return Map.of("success", false, "error", "Hotel not found: " + hotelId);
    }
    
    @Interface(
        name = "bookHotel",
        description = "Book a hotel room"
    )
    public Map<String, Object> bookHotel(Map<String, Object> params, Context ctx) {
        String hotelId = (String) params.get("hotelId");
        String checkIn = (String) params.get("checkIn");
        String checkOut = (String) params.get("checkOut");
        String guestName = (String) params.get("guestName");
        
        Map<String, Object> hotel = null;
        for (Map<String, Object> h : HOTELS) {
            if (h.get("id").equals(hotelId)) {
                hotel = h;
                break;
            }
        }
        
        if (hotel == null) {
            return Map.of("success", false, "error", "Hotel not found");
        }
        
        String bookingId = "BK" + (++bookingCounter);
        Map<String, Object> booking = new HashMap<>();
        booking.put("bookingId", bookingId);
        booking.put("hotelId", hotelId);
        booking.put("hotelName", hotel.get("name"));
        booking.put("checkIn", checkIn);
        booking.put("checkOut", checkOut);
        booking.put("guestName", guestName);
        booking.put("status", "CONFIRMED");
        booking.put("bookedBy", ctx.getDid());
        
        bookings.put(bookingId, booking);
        
        return Map.of("success", true, "message", "Booking confirmed", "booking", booking);
    }
    
    @Interface(
        name = "cancelBooking",
        description = "Cancel an existing booking"
    )
    public Map<String, Object> cancelBooking(Map<String, Object> params, Context ctx) {
        String bookingId = (String) params.get("bookingId");
        
        Map<String, Object> booking = bookings.get(bookingId);
        if (booking == null) {
            return Map.of("success", false, "error", "Booking not found");
        }
        
        booking.put("status", "CANCELLED");
        return Map.of("success", true, "message", "Booking cancelled", "booking", booking);
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
