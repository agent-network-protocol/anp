/**
 * @program: anp4java
 * @description: 最简 Spring Boot Agent 示例 - 对齐 Python simple_agent.py
 * @author: Ruitao.Zhai
 * @date: 2025-01-29
 */
package com.agentconnect.example.springboot;

import com.agentconnect.server.Context;
import com.agentconnect.server.annotation.AnpAgent;
import com.agentconnect.server.annotation.Interface;
import org.springframework.stereotype.Component;

import java.util.Map;

@Component
@AnpAgent(
    name = "Simple Agent",
    description = "A simple ANP agent built with Spring Boot",
    did = "did:wba:example.com:agent:simple",
    prefix = "/agent"
)
public class SimpleAgent {
    
    @Interface(
        name = "hello",
        description = "Say hello to someone"
    )
    public Map<String, Object> hello(Map<String, Object> params, Context ctx) {
        String name = (String) params.getOrDefault("name", "World");
        return Map.of("message", "Hello, " + name + "!");
    }
    
    @Interface(
        name = "add",
        description = "Add two numbers"
    )
    public Map<String, Object> add(Map<String, Object> params, Context ctx) {
        Number a = (Number) params.getOrDefault("a", 0);
        Number b = (Number) params.getOrDefault("b", 0);
        return Map.of("result", a.doubleValue() + b.doubleValue());
    }
    
    @Interface(
        name = "echo",
        description = "Echo the input message"
    )
    public Map<String, Object> echo(Map<String, Object> params, Context ctx) {
        String message = (String) params.getOrDefault("message", "");
        return Map.of(
            "echo", message,
            "length", message.length()
        );
    }
}
