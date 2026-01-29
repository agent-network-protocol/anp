/**
 * Calculator Agent Example - Aligned with Python OpenANP minimal_server.py
 * 
 * This package demonstrates:
 * - @Param annotation for direct parameter mapping (like Python's type hints)
 * - Primitive return types (int, double) instead of Map
 * - Clean API similar to Python's @interface decorator
 * 
 * Files:
 * - CalculatorAgent.java - Agent definition with @Param annotations
 * - CalculatorServer.java - HTTP server exposing the agent
 * - CalculatorClient.java - Client using ANPCrawler to call the agent
 * 
 * Usage:
 *   # Start server
 *   mvn exec:java -pl anp-examples \
 *     -Dexec.mainClass="com.agentconnect.example.calculator.CalculatorServer"
 *   
 *   # Run client (new terminal)
 *   mvn exec:java -pl anp-examples \
 *     -Dexec.mainClass="com.agentconnect.example.calculator.CalculatorClient"
 *   
 *   # Or test with curl
 *   curl -X POST http://localhost:8000/agent/rpc \
 *     -H "Content-Type: application/json" \
 *     -d '{"jsonrpc":"2.0","method":"add","params":{"a":10,"b":20},"id":1}'
 */
package com.agentconnect.example.calculator;
