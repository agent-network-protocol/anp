# ANP Java SDK

Agent Network Protocol (ANP) Java SDK - 完整的 Java 实现。

## 模块结构

```
java/
├── anp4j/                         # 核心 SDK（纯 Java，无框架依赖）
├── anp-spring-boot-starter/       # Spring Boot Starter（自动配置）
└── anp-examples/                  # 示例代码
```

| 模块 | 说明 | 依赖 |
|------|------|------|
| `anp4j` | 核心 SDK，不依赖任何框架 | - |
| `anp-spring-boot-starter` | Spring Boot 自动配置 | anp4j |
| `anp-examples` | 所有示例代码 | starter |

## 快速开始

### 安装到本地仓库

```bash
cd java
mvn clean install -DskipTests
```

### 引用方式

**不用 Spring Boot（纯 Java）：**

```xml
<dependency>
    <groupId>com.agentconnect</groupId>
    <artifactId>anp4j</artifactId>
    <version>1.0.0</version>
</dependency>
```

**用 Spring Boot：**

```xml
<dependency>
    <groupId>com.agentconnect</groupId>
    <artifactId>anp-spring-boot-starter</artifactId>
    <version>1.0.0</version>
</dependency>
```

---

## 方式一：Spring Boot（推荐）

### 1. 添加依赖

```xml
<dependency>
    <groupId>com.agentconnect</groupId>
    <artifactId>anp-spring-boot-starter</artifactId>
    <version>1.0.0</version>
</dependency>
```

### 2. 定义 Agent

```java
import com.agentconnect.server.annotation.*;
import com.agentconnect.server.Context;
import org.springframework.stereotype.Component;

@Component
@AnpAgent(
    name = "Hotel Agent",
    description = "酒店预订服务",
    did = "did:wba:example.com:hotel",
    prefix = "/hotel"
)
public class HotelAgent {
    
    @Interface(name = "search", description = "搜索酒店")
    public Map<String, Object> search(Map<String, Object> params, Context ctx) {
        String city = (String) params.get("city");
        return Map.of("hotels", List.of("Hotel A", "Hotel B"));
    }
    
    @Interface(name = "book", description = "预订酒店")
    public Map<String, Object> book(Map<String, Object> params, Context ctx) {
        return Map.of("bookingId", "BK" + System.currentTimeMillis());
    }
}
```

### 3. 启动应用

```java
@SpringBootApplication
public class Application {
    public static void main(String[] args) {
        SpringApplication.run(Application.class, args);
    }
}
```

### 4. 自动生成的端点

```
GET  http://localhost:8080/hotel/ad.json          # Agent 描述
GET  http://localhost:8080/hotel/interface.json   # OpenRPC 接口
POST http://localhost:8080/hotel/rpc              # JSON-RPC 端点
GET  http://localhost:8080/hotel/tools            # OpenAI Tools 格式
```

### 5. 测试

```bash
# 查看 Agent 描述
curl http://localhost:8080/hotel/ad.json | jq

# 搜索酒店
curl -X POST http://localhost:8080/hotel/rpc \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"search","params":{"city":"Tokyo"}}'
```

### 配置项 (application.yml)

```yaml
anp:
  enabled: true
  base-url: https://example.com
  auth:
    enabled: false
    exempt-paths:
      - /ad.json
      - /interface.json
```

---

## 方式二：纯 Java（不用 Spring）

### 1. 添加依赖

```xml
<dependency>
    <groupId>com.agentconnect</groupId>
    <artifactId>anp4j</artifactId>
    <version>1.0.0</version>
</dependency>
```

### 2. 定义 Agent

```java
import com.agentconnect.server.annotation.*;
import com.agentconnect.server.*;
import com.agentconnect.protocol.*;

@AnpAgent(name = "Hotel Agent", did = "did:wba:example.com:hotel")
public class HotelAgent {
    
    @Interface(name = "search")
    public Map<String, Object> search(Map<String, Object> params, Context ctx) {
        return Map.of("hotels", List.of("Hotel A", "Hotel B"));
    }
}
```

### 3. 创建 Handler 并集成 HTTP 框架

```java
AgentConfig config = AgentConfig.builder()
    .name("Hotel Agent")
    .did("did:wba:example.com:hotel")
    .baseUrl("http://localhost:8080")
    .prefix("/hotel")
    .build();

AgentHandler handler = new AgentHandler(new HotelAgent(), config);

// 用任何 HTTP 框架（Javalin, Vert.x, Netty, 原生 HttpServer...）
// GET  /hotel/ad.json         → handler.generateAgentDescription()
// GET  /hotel/interface.json  → handler.generateOpenRpc()
// POST /hotel/rpc             → handler.handleRequest(jsonRpcRequest, callerDid)
```

### 示例：使用 Java 原生 HttpServer

参考 `anp-examples/src/main/java/com/agentconnect/example/local/HotelServer.java`

---

## 调用远程 Agent

### 使用 ANPCrawler（推荐，支持 LLM）

```java
import com.agentconnect.crawler.*;

ANPCrawler crawler = new ANPCrawler(didDocPath, privateKeyPath);
crawler.fetchText("https://agent-connect.ai/mcp/agents/amap/ad.json");

// 列出可用方法
List<String> tools = crawler.listAvailableTools();

// 获取 OpenAI Tools 格式（给 LLM 用）
List<Map<String, Object>> openaiTools = crawler.getOpenAiTools();

// 调用方法
Map<String, Object> result = crawler.executeToolCall("maps_text_search", 
    Map.of("keywords", "咖啡厅", "city", "北京"));
```

### 使用 RemoteAgent

```java
import com.agentconnect.client.*;

ANPClient client = new ANPClient(myDid, privateKey);
RemoteAgent agent = RemoteAgent.discover("https://example.com/hotel/ad.json", client);

Map<String, Object> result = agent.invoke("search", Map.of("city", "Tokyo"));
```

---

## 模块详情

### anp4j - 核心 SDK

```
anp4j/src/main/java/com/agentconnect/
├── protocol/           # ANP 协议
│   ├── AgentConfig.java       # Agent 配置（Builder 模式）
│   ├── AgentDescription.java  # 生成 ad.json (JSON-LD)
│   ├── JsonRpc.java           # JSON-RPC 2.0
│   └── OpenRpcGenerator.java  # OpenRPC + OpenAI Tools
├── server/             # 服务端
│   ├── AgentHandler.java      # 核心请求处理器
│   ├── Context.java           # 请求上下文（DID, Session）
│   ├── SessionManager.java    # 会话管理
│   └── annotation/            # @AnpAgent, @Interface
├── client/             # 客户端
│   ├── ANPClient.java         # HTTP 客户端 + DID-WBA 认证
│   └── RemoteAgent.java       # 远程 Agent 代理
├── crawler/            # 爬虫
│   ├── ANPCrawler.java        # 爬虫式 Agent 发现
│   └── CrawlResult.java       # 结果容器
├── authentication/     # DID-WBA 认证
│   ├── DIDWBA.java
│   └── DIDWbaAuthHeader.java
└── utils/              # 工具类
    ├── CryptoTool.java        # Ed25519/ECDSA 签名
    └── DIDGenerator.java      # DID 文档生成
```

### anp-spring-boot-starter - Spring Boot 集成

```
anp-spring-boot-starter/src/main/java/com/agentconnect/spring/
├── AnpAutoConfiguration.java    # 自动配置
├── AnpAgentBeanProcessor.java   # 扫描 @AnpAgent Bean
├── AnpEndpointController.java   # REST 端点控制器
├── AnpProperties.java           # 配置属性
└── DidWbaAuthFilter.java        # DID-WBA 认证过滤器
```

### anp-examples - 示例代码

```
anp-examples/src/main/java/com/agentconnect/example/
├── didwba/             # DID-WBA 认证示例
│   ├── CreateDIDDocument.java     # 创建 DID 文档和密钥对
│   ├── ValidateDIDDocument.java   # 验证 DID 文档结构
│   └── AuthenticateAndVerify.java # 完整认证流程
├── client/             # 客户端示例
│   ├── RemoteAgentExample.java    # RemoteAgent 代理模式
│   └── LLMIntegrationExample.java # LLM 集成 (OpenAI Tools)
├── advanced/           # 高级功能示例
│   ├── AdvancedShopAgent.java     # 完整功能演示
│   └── AdvancedShopApplication.java
├── negotiation/        # 协议协商示例
│   └── NegotiationConceptExample.java  # 协商流程概念
├── ap2/                # AP2 支付协议示例
│   └── AP2ConceptExample.java     # 支付协议概念
├── local/              # 本地开发示例（无 Spring）
│   ├── HotelAgent.java
│   ├── HotelServer.java
│   └── HotelClient.java
├── calculator/         # Calculator 示例（@Param 注解）
├── online/             # 线上 Agent 调用
│   └── SmartAgentClient.java      # LLM 驱动的智能客户端
├── crawler/            # ANPCrawler 示例
│   └── AmapCrawlerExample.java
└── springboot/         # Spring Boot 示例
    ├── SimpleAgent.java           # 最简示例
    ├── HotelBookingAgent.java     # 酒店预订
    └── ShopAgent.java             # 购物车（Session 管理）
```

---

## 运行示例

### DID-WBA 认证示例

```bash
# 创建 DID 文档
mvn exec:java -pl anp-examples -Dexec.mainClass="com.agentconnect.example.didwba.CreateDIDDocument"

# 验证 DID 文档
mvn exec:java -pl anp-examples -Dexec.mainClass="com.agentconnect.example.didwba.ValidateDIDDocument"

# 认证流程演示
mvn exec:java -pl anp-examples -Dexec.mainClass="com.agentconnect.example.didwba.AuthenticateAndVerify"
```

### 客户端示例

```bash
# 先启动服务端
mvn exec:java -pl anp-examples -Dexec.mainClass="com.agentconnect.example.local.HotelServer"

# 然后运行客户端（新终端）
mvn exec:java -pl anp-examples -Dexec.mainClass="com.agentconnect.example.client.RemoteAgentExample"

# LLM 集成示例
mvn exec:java -pl anp-examples -Dexec.mainClass="com.agentconnect.example.client.LLMIntegrationExample"
```

### 高级功能示例

```bash
# 演示 content/link 模式、Information URL/Content 模式、Session 管理
mvn exec:java -pl anp-examples -Dexec.mainClass="com.agentconnect.example.advanced.AdvancedShopApplication"
```

### 协议概念示例

```bash
# 协议协商概念
mvn exec:java -pl anp-examples -Dexec.mainClass="com.agentconnect.example.negotiation.NegotiationConceptExample"

# AP2 支付协议概念
mvn exec:java -pl anp-examples -Dexec.mainClass="com.agentconnect.example.ap2.AP2ConceptExample"
```

### Spring Boot 示例

```bash
cd java
mvn exec:java -pl anp-examples -Dexec.mainClass="com.agentconnect.example.springboot.HotelApplication"
```

### 本地开发示例（无 Spring）

```bash
# 终端 1：启动服务端
mvn exec:java -pl anp-examples -Dexec.mainClass="com.agentconnect.example.local.HotelServer"

# 终端 2：运行客户端
mvn exec:java -pl anp-examples -Dexec.mainClass="com.agentconnect.example.local.HotelClient"
```

### LLM 智能客户端

```bash
export OPENAI_API_KEY=your-api-key
mvn exec:java -pl anp-examples -Dexec.mainClass="com.agentconnect.example.online.SmartAgentClient"
```

---

## 注解说明

### @AnpAgent

标记一个类为 ANP Agent：

| 属性 | 说明 | 必填 |
|------|------|------|
| `name` | Agent 名称 | 是 |
| `description` | Agent 描述 | 否 |
| `did` | DID 标识符 | 是 |
| `prefix` | URL 前缀 | 否 |

### @Interface

标记一个方法为可调用接口：

| 属性 | 说明 | 必填 |
|------|------|------|
| `name` | 方法名 | 否 |
| `description` | 方法描述 | 否 |

方法签名：

```java
public Map<String, Object> methodName(Map<String, Object> params, Context ctx)
```

也支持使用 `@Param` 注解的直接参数方式：

```java
public int add(@Param("a") int a, @Param("b") int b)
```

### @Param

标记方法参数：

| 属性 | 说明 | 必填 |
|------|------|------|
| `value` | 参数名 | 否 |
| `description` | 参数描述 | 否 |
| `required` | 是否必填（默认 true） | 否 |
| `defaultValue` | 默认值 | 否 |

---

## 依赖版本

| 依赖 | 版本 |
|------|------|
| Java | 11+ |
| Spring Boot | 2.7.18 |
| Jackson | 2.15.2 |
| Bouncy Castle | 1.70 |

---

## License

MIT License
