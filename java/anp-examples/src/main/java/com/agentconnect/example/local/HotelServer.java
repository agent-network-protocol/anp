/**
 * @program: anp4java
 * @description: 本地 Hotel Agent 服务端 - 启动 HTTP 服务器暴露 ANP 接口
 * @author: Ruitao.Zhai
 * @date: 2025-01-29
 */
package com.agentconnect.example.local;

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
 * 本地 Hotel Agent 服务器
 * 
 * 使用 Java 内置的 HttpServer，无需额外依赖。
 * 生产环境建议使用 Spring Boot。
 */
public class HotelServer {
    
    private static final Logger log = LoggerFactory.getLogger(HotelServer.class);
    
    private static final int PORT = 8000;
    private static final String BASE_URL = "http://localhost:" + PORT;
    
    private final AgentHandler handler;
    private HttpServer server;
    
    public HotelServer() {
        // 创建 Agent 配置
        AgentConfig config = AgentConfig.builder()
            .name("Hotel Booking Agent")
            .description("本地酒店预订 Agent - 提供搜索、预订、查询、取消等功能")
            .did("did:wba:localhost:hotel:booking")
            .baseUrl(BASE_URL)
            .prefix("/hotel")
            .build();
        
        // 创建 Agent 处理器
        this.handler = new AgentHandler(new HotelAgent(), config);
        
        log.info("HotelServer initialized");
    }
    
    /**
     * 启动服务器
     */
    public void start() throws IOException {
        server = HttpServer.create(new InetSocketAddress(PORT), 0);
        
        // GET /hotel/ad.json - Agent 描述
        server.createContext("/hotel/ad.json", this::handleAdJson);
        
        // GET /hotel/interface.json - OpenRPC 接口
        server.createContext("/hotel/interface.json", this::handleInterfaceJson);
        
        // POST /hotel/rpc - JSON-RPC 端点
        server.createContext("/hotel/rpc", this::handleRpc);
        
        // 根路径 - 欢迎信息
        server.createContext("/", this::handleRoot);
        
        server.setExecutor(null);
        server.start();
        
        System.out.println();
        System.out.println("=".repeat(60));
        System.out.println("🏨 Hotel Agent 服务器已启动！");
        System.out.println("=".repeat(60));
        System.out.println();
        System.out.println("服务端点：");
        System.out.println("  - Agent 描述: " + BASE_URL + "/hotel/ad.json");
        System.out.println("  - 接口文档:   " + BASE_URL + "/hotel/interface.json");
        System.out.println("  - RPC 端点:   " + BASE_URL + "/hotel/rpc");
        System.out.println();
        System.out.println("测试命令：");
        System.out.println("  # 查看 Agent 描述");
        System.out.println("  curl " + BASE_URL + "/hotel/ad.json | jq");
        System.out.println();
        System.out.println("  # 搜索东京酒店");
        System.out.println("  curl -X POST " + BASE_URL + "/hotel/rpc \\");
        System.out.println("    -H 'Content-Type: application/json' \\");
        System.out.println("    -d '{\"jsonrpc\":\"2.0\",\"method\":\"searchHotels\",\"params\":{\"city\":\"Tokyo\"},\"id\":1}'");
        System.out.println();
        System.out.println("按 Ctrl+C 停止服务器");
        System.out.println("=".repeat(60));
    }
    
    /**
     * 处理 Agent 描述请求
     */
    private void handleAdJson(HttpExchange exchange) throws IOException {
        if (!"GET".equals(exchange.getRequestMethod())) {
            sendError(exchange, 405, "Method Not Allowed");
            return;
        }
        
        String response = handler.generateAgentDescription();
        sendJson(exchange, 200, response);
        log.info("GET /hotel/ad.json");
    }
    
    /**
     * 处理接口文档请求
     */
    private void handleInterfaceJson(HttpExchange exchange) throws IOException {
        if (!"GET".equals(exchange.getRequestMethod())) {
            sendError(exchange, 405, "Method Not Allowed");
            return;
        }
        
        String response = handler.generateOpenRpc();
        sendJson(exchange, 200, response);
        log.info("GET /hotel/interface.json");
    }
    
    /**
     * 处理 RPC 请求
     */
    private void handleRpc(HttpExchange exchange) throws IOException {
        if (!"POST".equals(exchange.getRequestMethod())) {
            sendError(exchange, 405, "Method Not Allowed");
            return;
        }
        
        // 读取请求体
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
        
        // 从请求头获取调用者 DID（如果有）
        String callerDid = exchange.getRequestHeaders().getFirst("X-Caller-DID");
        if (callerDid == null) {
            callerDid = "anonymous";
        }
        
        // 处理 RPC 请求
        String response = handler.handleRequest(requestBody, callerDid);
        sendJson(exchange, 200, response);
        
        log.info("POST /hotel/rpc - caller: {}", callerDid);
    }
    
    /**
     * 处理根路径请求
     */
    private void handleRoot(HttpExchange exchange) throws IOException {
        String html = "<!DOCTYPE html>\n" +
            "<html>\n" +
            "<head><title>Hotel Agent</title></head>\n" +
            "<body>\n" +
            "<h1>🏨 Hotel Booking Agent</h1>\n" +
            "<p>本地 ANP Agent 服务器</p>\n" +
            "<h2>端点</h2>\n" +
            "<ul>\n" +
            "<li><a href=\"/hotel/ad.json\">/hotel/ad.json</a> - Agent 描述</li>\n" +
            "<li><a href=\"/hotel/interface.json\">/hotel/interface.json</a> - 接口文档</li>\n" +
            "<li>/hotel/rpc - JSON-RPC 端点 (POST)</li>\n" +
            "</ul>\n" +
            "<h2>可用方法</h2>\n" +
            "<ul>\n" +
            "<li>searchHotels - 搜索酒店</li>\n" +
            "<li>getHotelDetails - 获取酒店详情</li>\n" +
            "<li>bookHotel - 预订酒店</li>\n" +
            "<li>getBooking - 查询预订</li>\n" +
            "<li>cancelBooking - 取消预订</li>\n" +
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
    
    /**
     * 停止服务器
     */
    public void stop() {
        if (server != null) {
            server.stop(0);
            log.info("Server stopped");
        }
    }
    
    public static void main(String[] args) throws Exception {
        HotelServer server = new HotelServer();
        server.start();
        
        // 添加关闭钩子
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            System.out.println("\n正在停止服务器...");
            server.stop();
        }));
        
        // 保持运行
        Thread.currentThread().join();
    }
}
