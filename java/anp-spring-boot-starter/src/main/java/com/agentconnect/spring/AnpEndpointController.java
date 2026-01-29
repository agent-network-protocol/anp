/**
 * @program: anp4java
 * @description: ANP REST 端点控制器
 * @author: Ruitao.Zhai
 * @date: 2025-01-21
 **/
package com.agentconnect.spring;

import com.agentconnect.server.AgentHandler;
import com.agentconnect.server.Context;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import java.util.HashMap;
import java.util.Map;

/**
 * ANP 端点控制器
 * 
 * 根据 Agent 的 prefix 自动注册以下端点：
 * - GET  {agent.prefix}/ad.json        - Agent Description
 * - GET  {agent.prefix}/interface.json - OpenRPC Interface
 * - POST {agent.prefix}/rpc            - JSON-RPC Endpoint
 * - GET  {agent.prefix}/tools          - OpenAI Tools format
 * 
 * 支持路径模式匹配，如 /hotel/ad.json, /travel/ad.json 等
 */
@RestController
public class AnpEndpointController {
    
    private static final Logger log = LoggerFactory.getLogger(AnpEndpointController.class);
    
    private final AnpAgentBeanProcessor beanProcessor;
    private final AnpProperties properties;
    
    public AnpEndpointController(AnpAgentBeanProcessor beanProcessor, AnpProperties properties) {
        this.beanProcessor = beanProcessor;
        this.properties = properties;
        log.info("ANP Endpoint Controller initialized");
    }
    
    /**
     * Agent Description endpoint - matches any prefix
     * Examples: /hotel/ad.json, /travel/ad.json, /ad.json
     */
    @GetMapping(value = {"/{prefix}/ad.json", "/ad.json"}, produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<String> getAgentDescription(
            @PathVariable(required = false) String prefix,
            HttpServletRequest request) {
        String actualPrefix = prefix != null ? "/" + prefix : "";
        
        AgentHandler handler = findHandlerByPrefix(actualPrefix);
        if (handler == null) {
            log.warn("No handler found for prefix: {}", actualPrefix);
            return ResponseEntity.notFound().build();
        }
        
        String baseUrl = resolveBaseUrl(request);
        log.debug("Generating ad.json for prefix: {}, baseUrl: {}", actualPrefix, baseUrl);
        return ResponseEntity.ok(handler.generateAgentDescription(baseUrl));
    }
    
    /**
     * OpenRPC Interface endpoint
     */
    @GetMapping(value = {"/{prefix}/interface.json", "/interface.json"}, produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<String> getOpenRpcInterface(
            @PathVariable(required = false) String prefix,
            HttpServletRequest request) {
        String actualPrefix = prefix != null ? "/" + prefix : "";
        
        AgentHandler handler = findHandlerByPrefix(actualPrefix);
        if (handler == null) {
            return ResponseEntity.notFound().build();
        }
        
        String baseUrl = resolveBaseUrl(request);
        String rpcUrl = baseUrl + actualPrefix + "/rpc";
        return ResponseEntity.ok(handler.generateOpenRpc(rpcUrl));
    }
    
    /**
     * JSON-RPC Endpoint
     */
    @PostMapping(value = {"/{prefix}/rpc", "/rpc"}, 
                 consumes = MediaType.APPLICATION_JSON_VALUE, 
                 produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<String> handleRpc(
            @PathVariable(required = false) String prefix,
            @RequestBody String requestBody, 
            HttpServletRequest request) {
        String actualPrefix = prefix != null ? "/" + prefix : "";
        
        AgentHandler handler = findHandlerByPrefix(actualPrefix);
        if (handler == null) {
            return ResponseEntity.notFound().build();
        }
        
        String callerDid = DidWbaAuthFilter.getCallerDid(request);
        Map<String, Object> authResult = DidWbaAuthFilter.getAuthResult(request);
        Map<String, String> headers = extractHeaders(request);
        
        Context context = handler.createContext(callerDid, authResult, headers);
        
        String response = handler.handleRequest(requestBody, context);
        return ResponseEntity.ok(response);
    }
    
    /**
     * OpenAI Tools format endpoint
     */
    @GetMapping(value = {"/{prefix}/tools", "/tools"}, produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<?> getOpenAITools(
            @PathVariable(required = false) String prefix,
            HttpServletRequest request) {
        String actualPrefix = prefix != null ? "/" + prefix : "";
        
        AgentHandler handler = findHandlerByPrefix(actualPrefix);
        if (handler == null) {
            return ResponseEntity.notFound().build();
        }
        
        return ResponseEntity.ok(handler.getOpenAITools());
    }
    
    /**
     * Extract prefix from request path
     * e.g., /hotel/ad.json -> /hotel
     *       /ad.json -> (empty)
     */
    private String extractPrefix(String path, String suffix) {
        if (path.endsWith(suffix)) {
            String prefix = path.substring(0, path.length() - suffix.length());
            return prefix.isEmpty() ? "" : prefix;
        }
        return "";
    }
    
    /**
     * Find handler by prefix
     */
    private AgentHandler findHandlerByPrefix(String prefix) {
        // First try exact match
        for (AgentHandler handler : beanProcessor.getHandlers().values()) {
            if (handler.getConfig().getPrefix().equals(prefix)) {
                return handler;
            }
        }
        
        // If no prefix specified, return first handler
        if (prefix.isEmpty()) {
            return beanProcessor.getFirstHandler();
        }
        
        return null;
    }
    
    private String resolveBaseUrl(HttpServletRequest request) {
        if (properties.getBaseUrl() != null && !properties.getBaseUrl().isEmpty()) {
            return properties.getBaseUrl();
        }
        
        String scheme = request.getScheme();
        String serverName = request.getServerName();
        int serverPort = request.getServerPort();
        
        StringBuilder url = new StringBuilder();
        url.append(scheme).append("://").append(serverName);
        
        if (("http".equals(scheme) && serverPort != 80) ||
            ("https".equals(scheme) && serverPort != 443)) {
            url.append(":").append(serverPort);
        }
        
        return url.toString();
    }
    
    private Map<String, String> extractHeaders(HttpServletRequest request) {
        Map<String, String> headers = new HashMap<>();
        var headerNames = request.getHeaderNames();
        while (headerNames.hasMoreElements()) {
            String name = headerNames.nextElement();
            headers.put(name.toLowerCase(), request.getHeader(name));
        }
        return headers;
    }
}
