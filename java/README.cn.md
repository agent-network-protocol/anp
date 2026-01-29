# ANP Java SDK

Agent Network Protocol (ANP) Java SDK - 完整的 Java 实现。

## 模块结构

```
java/
├── anp4j/                         # 核心 SDK（无框架依赖）
├── anp-spring-boot-starter/       # Spring Boot Starter（自动配置）
└── anp-examples/                  # 示例代码
```

| 模块 | 说明 | Maven 坐标 |
|------|------|------------|
| `anp4j` | 核心 SDK，不依赖任何框架 | `com.agentconnect:anp4j:1.0.0` |
| `anp-spring-boot-starter` | Spring Boot 自动配置 | `com.agentconnect:anp-spring-boot-starter:1.0.0` |
| `anp-examples` | 示例代码 | - |

## 快速开始

### 安装

```bash
cd java
mvn clean install -DskipTests
```

### 引用

**不用 Spring Boot：**
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

## Spring Boot 使用

```java
@Component
@AnpAgent(name = "Hotel", did = "did:wba:example.com:hotel", prefix = "/hotel")
public class HotelAgent {
    
    @Interface(name = "search", description = "搜索酒店")
    public Map<String, Object> search(Map<String, Object> params, Context ctx) {
        return Map.of("hotels", List.of("Hotel A", "Hotel B"));
    }
}
```

启动后自动暴露端点：
- `GET /hotel/ad.json` - Agent 描述
- `POST /hotel/rpc` - JSON-RPC 端点

## 纯 Java 使用

```java
AgentHandler handler = new AgentHandler(new HotelAgent(), config);
String adJson = handler.generateAgentDescription();
String response = handler.handleRequest(jsonRpcRequest, callerDid);
```

## 运行示例

```bash
# Spring Boot 示例
mvn exec:java -pl anp-examples -Dexec.mainClass="com.agentconnect.example.springboot.HotelApplication"

# 本地示例（无 Spring）
mvn exec:java -pl anp-examples -Dexec.mainClass="com.agentconnect.example.local.HotelServer"
```

## License

MIT License
