/**
 * @program: anp4java
 * @author: Ruitao.Zhai
 * @date: 2025-01-29
 */
package com.agentconnect.example.calculator;

import com.agentconnect.server.annotation.AnpAgent;
import com.agentconnect.server.annotation.Interface;
import com.agentconnect.server.annotation.Param;

/**
 * Calculator Agent - Aligned with Python OpenANP minimal_server.py
 * 
 * Demonstrates the new @Param annotation for direct parameter mapping.
 * 
 * Python equivalent:
 *   @anp_agent(AgentConfig(name="Calculator", did="did:wba:example.com:calculator", prefix="/agent"))
 *   class CalculatorAgent:
 *       @interface
 *       async def add(self, a: int, b: int) -> int:
 *           return a + b
 */
@AnpAgent(
    name = "Calculator",
    description = "A simple calculator agent",
    did = "did:wba:example.com:calculator",
    prefix = "/agent"
)
public class CalculatorAgent {
    
    @Interface(name = "add", description = "Calculate the sum of two numbers")
    public int add(
        @Param(value = "a", description = "First number") int a, 
        @Param(value = "b", description = "Second number") int b
    ) {
        return a + b;
    }
    
    @Interface(name = "multiply", description = "Calculate the product of two numbers")
    public int multiply(
        @Param(value = "a", description = "First number") int a, 
        @Param(value = "b", description = "Second number") int b
    ) {
        return a * b;
    }
    
    @Interface(name = "subtract", description = "Calculate the difference of two numbers")
    public int subtract(
        @Param("a") int a, 
        @Param("b") int b
    ) {
        return a - b;
    }
    
    @Interface(name = "divide", description = "Calculate the quotient of two numbers")
    public double divide(
        @Param("a") double a, 
        @Param(value = "b", description = "Divisor (must not be zero)") double b
    ) {
        if (b == 0) {
            throw new ArithmeticException("Division by zero");
        }
        return a / b;
    }
}
