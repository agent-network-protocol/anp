/**
 * @program: anp4java
 * @author: Ruitao.Zhai
 * @date: 2025-01-29
 */
package com.agentconnect.protocol;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.util.*;

/**
 * Agent Description (ad.json) generator.
 * 
 * Generates JSON-LD formatted ad.json documents following the ANP specification.
 */
public final class AgentDescription {
    
    private static final ObjectMapper objectMapper = new ObjectMapper();
    
    private AgentDescription() {}
    
    /**
     * Generate ad.json document.
     * 
     * @param config Agent configuration
     * @param methods RPC method information list
     * @param informations Information list
     * @param baseUrl Base URL for generating interface URLs
     * @return ad.json as Map
     */
    public static Map<String, Object> generate(
            AgentConfig config,
            List<RPCMethodInfo> methods,
            List<Information> informations,
            String baseUrl) {
        
        Map<String, Object> ad = new LinkedHashMap<>();
        
        // JSON-LD Context
        Map<String, Object> context = new LinkedHashMap<>();
        context.put("ad", "https://agent-network-protocol.com/ad/");
        context.put("did", "https://w3id.org/did/");
        context.put("schema", "https://schema.org/");
        ad.put("@context", context);
        
        // Type
        ad.put("@type", "ad:AgentDescription");
        
        // Basic info
        ad.put("name", config.getName());
        ad.put("did", config.getDid());
        ad.put("description", config.getDescription());
        
        // Generate interfaces
        List<Map<String, Object>> interfaces = generateInterfaces(config, methods, baseUrl);
        if (!interfaces.isEmpty()) {
            ad.put("interfaces", interfaces);
        }
        
        // Generate informations
        if (informations != null && !informations.isEmpty()) {
            List<Map<String, Object>> infoList = new ArrayList<>();
            for (Information info : informations) {
                infoList.add(info.toMap(baseUrl + config.getPrefix()));
            }
            ad.put("Infomations", infoList);
        }
        
        return ad;
    }
    
    /**
     * Generate interfaces section.
     */
    private static List<Map<String, Object>> generateInterfaces(
            AgentConfig config,
            List<RPCMethodInfo> methods,
            String baseUrl) {
        
        List<Map<String, Object>> interfaces = new ArrayList<>();
        String prefix = config.getPrefix();
        String fullBaseUrl = baseUrl + prefix;
        
        // Separate content mode and link mode methods
        List<RPCMethodInfo> contentMethods = new ArrayList<>();
        List<RPCMethodInfo> linkMethods = new ArrayList<>();
        
        for (RPCMethodInfo method : methods) {
            if (method.getMode() == RPCMethodInfo.Mode.LINK) {
                linkMethods.add(method);
            } else {
                contentMethods.add(method);
            }
        }
        
        // Add main interface.json for content mode methods
        if (!contentMethods.isEmpty()) {
            Map<String, Object> mainInterface = new LinkedHashMap<>();
            mainInterface.put("type", "StructuredInterface");
            mainInterface.put("protocol", "openrpc");
            mainInterface.put("url", fullBaseUrl + "/interface.json");
            mainInterface.put("description", config.getName() + " JSON-RPC interface");
            interfaces.add(mainInterface);
        }
        
        // Add individual interfaces for link mode methods
        for (RPCMethodInfo method : linkMethods) {
            Map<String, Object> linkInterface = new LinkedHashMap<>();
            linkInterface.put("type", "StructuredInterface");
            linkInterface.put("protocol", "openrpc");
            linkInterface.put("url", fullBaseUrl + "/interface/" + method.getName() + ".json");
            linkInterface.put("description", method.getDescription());
            interfaces.add(linkInterface);
        }
        
        return interfaces;
    }
    
    /**
     * Convert to JSON string.
     */
    public static String toJson(Map<String, Object> ad) throws JsonProcessingException {
        return objectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(ad);
    }
}
