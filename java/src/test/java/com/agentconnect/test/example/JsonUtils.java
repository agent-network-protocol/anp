package com.agentconnect.test.example;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;

public class JsonUtils {
    
    private static final Logger logger = LoggerFactory.getLogger(JsonUtils.class);
    private static final ObjectMapper objectMapper = new ObjectMapper();
    
    /**
     * Convert object to canonical JSON string
     * This is a simplified implementation of JSON canonicalization
     * For production use, consider using a proper JSON canonicalization library
     * 
     * @param obj Object to canonicalize
     * @return Canonical JSON string
     */
    public static String encodeCanonicalJson(Object obj) {
        try {
            // Convert to normalized form
            Object normalized = normalizeObject(obj);
            return objectMapper.writeValueAsString(normalized);
        } catch (Exception e) {
            logger.error("Failed to encode canonical JSON", e);
            throw new RuntimeException("Failed to encode canonical JSON", e);
        }
    }
    
    /**
     * Normalize object for canonical representation
     * - Sort all object keys
     * - Recursively normalize nested objects and arrays
     */
    @SuppressWarnings("unchecked")
    private static Object normalizeObject(Object obj) {
        if (obj == null) {
            return null;
        } else if (obj instanceof Map) {
            Map<String, Object> map = (Map<String, Object>) obj;
            Map<String, Object> sortedMap = new TreeMap<>(); // TreeMap automatically sorts keys
            
            for (Map.Entry<String, Object> entry : map.entrySet()) {
                sortedMap.put(entry.getKey(), normalizeObject(entry.getValue()));
            }
            return sortedMap;
            
        } else if (obj instanceof List) {
            List<Object> list = (List<Object>) obj;
            List<Object> normalizedList = new ArrayList<>();
            
            for (Object item : list) {
                normalizedList.add(normalizeObject(item));
            }
            return normalizedList;
            
        } else if (obj instanceof Object[]) {
            Object[] array = (Object[]) obj;
            List<Object> normalizedList = new ArrayList<>();
            
            for (Object item : array) {
                normalizedList.add(normalizeObject(item));
            }
            return normalizedList;
            
        } else {
            // Primitive types, strings, etc. - return as is
            return obj;
        }
    }
    
    /**
     * Compare two objects using canonical JSON representation
     * 
     * @param obj1 First object
     * @param obj2 Second object
     * @return true if canonical representations are equal
     */
    public static boolean compareCanonical(Object obj1, Object obj2) {
        try {
            String canonical1 = encodeCanonicalJson(obj1);
            String canonical2 = encodeCanonicalJson(obj2);
            return canonical1.equals(canonical2);
        } catch (Exception e) {
            logger.error("Failed to compare canonical JSON", e);
            return false;
        }
    }
    
    /**
     * Pretty print JSON object
     * 
     * @param obj Object to print
     * @return Pretty printed JSON string
     */
    public static String prettyPrint(Object obj) {
        try {
            return objectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(obj);
        } catch (Exception e) {
            logger.error("Failed to pretty print JSON", e);
            return obj.toString();
        }
    }
    
    /**
     * Parse JSON string to Map
     * 
     * @param jsonString JSON string
     * @return Map representation
     */
    @SuppressWarnings("unchecked")
    public static Map<String, Object> parseJson(String jsonString) {
        try {
            return objectMapper.readValue(jsonString, Map.class);
        } catch (Exception e) {
            logger.error("Failed to parse JSON string", e);
            throw new RuntimeException("Failed to parse JSON string", e);
        }
    }
    
    /**
     * Convert object to JSON string
     * 
     * @param obj Object to convert
     * @return JSON string
     */
    public static String toJsonString(Object obj) {
        try {
            return objectMapper.writeValueAsString(obj);
        } catch (Exception e) {
            logger.error("Failed to convert object to JSON string", e);
            throw new RuntimeException("Failed to convert object to JSON string", e);
        }
    }
}