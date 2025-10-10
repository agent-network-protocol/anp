#!/bin/bash
# Test script for simple_agent.py

echo "Testing Simple FastANP Agent"
echo "=============================="
echo

# Wait for server to be ready
sleep 2

echo "1. Testing Agent Description endpoint..."
curl -s http://localhost:8000/ad.json | jq '.' || echo "Failed to get ad.json"
echo

echo "2. Testing Information endpoint..."
curl -s http://localhost:8000/info/capabilities.json | jq '.' || echo "Failed to get capabilities"
echo

echo "3. Testing hello method..."
curl -s -X POST http://localhost:8000/rpc \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"hello","params":{"name":"Alice"}}' | jq '.'
echo

echo "4. Testing add method..."
curl -s -X POST http://localhost:8000/rpc \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":2,"method":"add","params":{"a":5,"b":3}}' | jq '.'
echo

echo "All tests completed!"

