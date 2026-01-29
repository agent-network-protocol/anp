/**
 * @program: anp4java
 * @author: Ruitao.Zhai
 * @date: 2025-01-29
 */
package com.agentconnect.example.calculator;

import com.agentconnect.protocol.AgentConfig;
import com.agentconnect.server.AgentHandler;
import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpExchange;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;

/**
 * Calculator Agent Server - Aligned with Python OpenANP minimal_server.py
 */
public class CalculatorServer {
    
    private static final Logger log = LoggerFactory.getLogger(CalculatorServer.class);
    private static final int PORT = 8000;
    private static final String BASE_URL = "http://localhost:" + PORT;
    
    private final AgentHandler handler;
    private HttpServer server;
    
    public CalculatorServer() {
        AgentConfig config = AgentConfig.builder()
            .name("Calculator")
            .description("A simple calculator agent")
            .did("did:wba:example.com:calculator")
            .baseUrl(BASE_URL)
            .prefix("/agent")
            .build();
        
        this.handler = new AgentHandler(new CalculatorAgent(), config);
    }
    
    public void start() throws IOException {
        server = HttpServer.create(new InetSocketAddress(PORT), 0);
        
        server.createContext("/agent/ad.json", this::handleAdJson);
        server.createContext("/agent/interface.json", this::handleInterfaceJson);
        server.createContext("/agent/rpc", this::handleRpc);
        server.createContext("/", this::handleRoot);
        
        server.setExecutor(null);
        server.start();
        
        System.out.println();
        System.out.println("=".repeat(60));
        System.out.println("Starting Minimal ANP Server (Calculator)...");
        System.out.println("=".repeat(60));
        System.out.println();
        System.out.println("Endpoints:");
        System.out.println("  Agent Description: " + BASE_URL + "/agent/ad.json");
        System.out.println("  OpenRPC Document:  " + BASE_URL + "/agent/interface.json");
        System.out.println("  JSON-RPC Endpoint: " + BASE_URL + "/agent/rpc");
        System.out.println();
        System.out.println("Test commands:");
        System.out.println("  curl -X POST " + BASE_URL + "/agent/rpc \\");
        System.out.println("    -H 'Content-Type: application/json' \\");
        System.out.println("    -d '{\"jsonrpc\":\"2.0\",\"method\":\"add\",\"params\":{\"a\":10,\"b\":20},\"id\":1}'");
        System.out.println();
        System.out.println("Press Ctrl+C to stop");
        System.out.println("=".repeat(60));
    }
    
    private void handleAdJson(HttpExchange exchange) throws IOException {
        if (!"GET".equals(exchange.getRequestMethod())) {
            sendError(exchange, 405, "Method Not Allowed");
            return;
        }
        
        String response = handler.generateAgentDescription();
        sendJson(exchange, 200, response);
        log.info("GET /agent/ad.json");
    }
    
    private void handleInterfaceJson(HttpExchange exchange) throws IOException {
        if (!"GET".equals(exchange.getRequestMethod())) {
            sendError(exchange, 405, "Method Not Allowed");
            return;
        }
        
        String response = handler.generateOpenRpc();
        sendJson(exchange, 200, response);
        log.info("GET /agent/interface.json");
    }
    
    private void handleRpc(HttpExchange exchange) throws IOException {
        if (!"POST".equals(exchange.getRequestMethod())) {
            sendError(exchange, 405, "Method Not Allowed");
            return;
        }
        
        String requestBody;
        try (InputStream is = exchange.getRequestBody();
             BufferedReader reader = new BufferedReader(new InputStreamReader(is, StandardCharsets.UTF_8))) {
            StringBuilder sb = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                sb.append(line);
            }
            requestBody = sb.toString();
        }
        
        String callerDid = exchange.getRequestHeaders().getFirst("X-Caller-DID");
        if (callerDid == null) {
            callerDid = "anonymous";
        }
        
        String response = handler.handleRequest(requestBody, callerDid);
        sendJson(exchange, 200, response);
        
        log.info("POST /agent/rpc - caller: {}", callerDid);
    }
    
    private void handleRoot(HttpExchange exchange) throws IOException {
        String html = "<!DOCTYPE html>\n" +
            "<html>\n" +
            "<head><title>Calculator Agent</title></head>\n" +
            "<body>\n" +
            "<h1>Calculator Agent</h1>\n" +
            "<p>ANP Agent - Aligned with Python OpenANP minimal_server.py</p>\n" +
            "<h2>Endpoints</h2>\n" +
            "<ul>\n" +
            "<li><a href=\"/agent/ad.json\">/agent/ad.json</a> - Agent Description</li>\n" +
            "<li><a href=\"/agent/interface.json\">/agent/interface.json</a> - OpenRPC Document</li>\n" +
            "<li>/agent/rpc - JSON-RPC Endpoint (POST)</li>\n" +
            "</ul>\n" +
            "<h2>Available Methods</h2>\n" +
            "<ul>\n" +
            "<li>add(a, b) - Sum of two numbers</li>\n" +
            "<li>multiply(a, b) - Product of two numbers</li>\n" +
            "<li>subtract(a, b) - Difference of two numbers</li>\n" +
            "<li>divide(a, b) - Quotient of two numbers</li>\n" +
            "</ul>\n" +
            "</body>\n" +
            "</html>\n";
        
        exchange.getResponseHeaders().set("Content-Type", "text/html; charset=utf-8");
        byte[] bytes = html.getBytes(StandardCharsets.UTF_8);
        exchange.sendResponseHeaders(200, bytes.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(bytes);
        }
    }
    
    private void sendJson(HttpExchange exchange, int status, String json) throws IOException {
        exchange.getResponseHeaders().set("Content-Type", "application/json; charset=utf-8");
        exchange.getResponseHeaders().set("Access-Control-Allow-Origin", "*");
        byte[] bytes = json.getBytes(StandardCharsets.UTF_8);
        exchange.sendResponseHeaders(status, bytes.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(bytes);
        }
    }
    
    private void sendError(HttpExchange exchange, int status, String message) throws IOException {
        String json = "{\"error\":\"" + message + "\"}";
        sendJson(exchange, status, json);
    }
    
    public void stop() {
        if (server != null) {
            server.stop(0);
            log.info("Server stopped");
        }
    }
    
    public static void main(String[] args) throws Exception {
        CalculatorServer server = new CalculatorServer();
        server.start();
        
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            System.out.println("\nStopping server...");
            server.stop();
        }));
        
        Thread.currentThread().join();
    }
}
