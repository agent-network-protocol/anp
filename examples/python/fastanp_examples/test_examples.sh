#!/bin/bash
# Quick test script for FastANP examples

set -e

echo "================================"
echo "Testing FastANP Examples"
echo "================================"
echo ""

# Test simple_agent
echo "1. Testing simple_agent.py..."
python -c "
import sys
sys.path.insert(0, '.')
from simple_agent import app, anp
assert anp.name == 'Simple Agent'
assert len(anp.interface_manager.functions) == 1
print('   ✓ simple_agent.py imports successfully')
"

# Test simple_agent_with_context
echo "2. Testing simple_agent_with_context.py..."
python -c "
import sys
sys.path.insert(0, '.')
from simple_agent_with_context import app, anp
assert anp.name == 'Simple Agent with Context'
assert len(anp.interface_manager.functions) == 1
# Check that counter has context param
for func in anp.interface_manager.functions.values():
    assert func.has_context_param == True
print('   ✓ simple_agent_with_context.py imports successfully')
"

# Test hotel_booking_agent
echo "3. Testing hotel_booking_agent.py..."
python -c "
import sys
sys.path.insert(0, '.')
from hotel_booking_agent import app, anp
assert anp.name == 'Hotel Booking Assistant'
assert len(anp.interface_manager.functions) == 2
print('   ✓ hotel_booking_agent.py imports successfully')
"

echo ""
echo "================================"
echo "✓ All examples passed!"
echo "================================"

