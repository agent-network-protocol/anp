#!/bin/bash
# Test script for hybrid_agent.py
# Tests all OpenANP features: ad.json, interface.json, RPC calls

# Don't exit on error - we want to see all test results
set +e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
TRAVEL_BASE_URL="http://localhost:8001"
TRAVEL_PREFIX="/travel"
HOTEL_BASE_URL="http://localhost:8000"

# Test counter
TESTS_PASSED=0
TESTS_FAILED=0

# Helper functions
print_header() {
    echo ""
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
}

print_test() {
    echo ""
    echo -e "${YELLOW}🧪 Test: $1${NC}"
}

print_success() {
    echo -e "${GREEN}✅ PASS: $1${NC}"
    ((TESTS_PASSED++))
}

print_failure() {
    echo -e "${RED}❌ FAIL: $1${NC}"
    ((TESTS_FAILED++))
}

print_info() {
    echo -e "${BLUE}ℹ️  $1${NC}"
}

# Check if services are running
check_services() {
    print_header "Pre-flight Check"

    # Check Hotel Agent
    print_test "Hotel Agent (port 8000)"
    if curl -sf "${HOTEL_BASE_URL}/hotel/ad.json" > /dev/null; then
        print_success "Hotel Agent is running"
    else
        print_failure "Hotel Agent not running on port 8000"
        print_info "Start with: uv run uvicorn anp.fastanp.example.simple_server:app --port 8000"
        exit 1
    fi

    # Check Travel Agent
    print_test "Travel Agent (port 8001)"
    TRAVEL_CHECK=$(curl -sf "${TRAVEL_BASE_URL}${TRAVEL_PREFIX}/ad.json" 2>&1)
    if [ $? -eq 0 ] && [ -n "$TRAVEL_CHECK" ]; then
        print_success "Travel Agent is running"
    else
        print_failure "Travel Agent not running on port 8001"
        print_info "Error: $TRAVEL_CHECK"
        print_info "Start with: uv run uvicorn anp.fastanp.example.hybrid_agent:app --port 8001"
        print_info "Continuing with available tests..."
        TRAVEL_AGENT_DOWN=1
    fi
}

# Test ad.json (Agent Description)
test_ad_json() {
    print_header "Test 1: Agent Description (ad.json)"

    if [ "$TRAVEL_AGENT_DOWN" = "1" ]; then
        print_info "Skipping - Travel Agent not running"
        return
    fi

    print_test "Fetch ad.json"
    AD_JSON=$(curl -sf "${TRAVEL_BASE_URL}${TRAVEL_PREFIX}/ad.json" 2>&1)
    CURL_EXIT=$?

    if [ $CURL_EXIT -eq 0 ] && [ -n "$AD_JSON" ]; then
        print_success "ad.json fetched successfully"
    else
        print_failure "Failed to fetch ad.json (exit code: $CURL_EXIT)"
        print_info "Response: ${AD_JSON:0:100}"
        return
    fi

    print_test "Validate JSON-LD fields"

    # Check @context
    if echo "$AD_JSON" | jq -e '.["@context"]' > /dev/null; then
        print_success "@context exists"
    else
        print_failure "@context missing"
    fi

    # Check @type
    TYPE=$(echo "$AD_JSON" | jq -r '.["@type"]')
    if [ "$TYPE" = "ad:AgentDescription" ]; then
        print_success "@type = ad:AgentDescription"
    else
        print_failure "@type incorrect: $TYPE"
    fi

    # Check @id
    if echo "$AD_JSON" | jq -e '.["@id"]' > /dev/null; then
        print_success "@id exists"
    else
        print_failure "@id missing"
    fi

    # Check name
    NAME=$(echo "$AD_JSON" | jq -r '.name')
    if [ "$NAME" = "Travel Agent" ]; then
        print_success "name = Travel Agent"
    else
        print_failure "name incorrect: $NAME"
    fi

    # Check interfaces
    INTERFACE_COUNT=$(echo "$AD_JSON" | jq '.interfaces | length')
    if [ "$INTERFACE_COUNT" -gt 0 ]; then
        print_success "interfaces exist ($INTERFACE_COUNT found)"
    else
        print_failure "No interfaces found"
    fi
}

# Test interface.json (OpenRPC)
test_interface_json() {
    print_header "Test 2: Interface Document (interface.json)"

    if [ "$TRAVEL_AGENT_DOWN" = "1" ]; then
        print_info "Skipping - Travel Agent not running"
        return
    fi

    print_test "Fetch interface.json"
    INTERFACE_JSON=$(curl -sf "${TRAVEL_BASE_URL}${TRAVEL_PREFIX}/interface.json" 2>&1)
    CURL_EXIT=$?

    if [ $CURL_EXIT -eq 0 ] && [ -n "$INTERFACE_JSON" ]; then
        print_success "interface.json fetched successfully"
    else
        print_failure "Failed to fetch interface.json (exit code: $CURL_EXIT)"
        print_info "Response: ${INTERFACE_JSON:0:100}"
        return
    fi

    print_test "Validate OpenRPC format"

    # Check openrpc version
    OPENRPC=$(echo "$INTERFACE_JSON" | jq -r '.openrpc')
    if [ "$OPENRPC" = "1.3.2" ]; then
        print_success "OpenRPC version = 1.3.2"
    else
        print_failure "OpenRPC version incorrect: $OPENRPC"
    fi

    # Check methods
    METHOD_COUNT=$(echo "$INTERFACE_JSON" | jq '.methods | length')
    if [ "$METHOD_COUNT" -eq 2 ]; then
        print_success "Found 2 methods"
    else
        print_failure "Expected 2 methods, found $METHOD_COUNT"
    fi

    # Check plan_trip method
    print_test "Validate plan_trip method"
    PLAN_TRIP=$(echo "$INTERFACE_JSON" | jq '.methods[] | select(.name == "plan_trip")')

    if [ -n "$PLAN_TRIP" ]; then
        print_success "plan_trip method exists"

        # Check params (should be array of ContentDescriptor)
        PARAMS_COUNT=$(echo "$PLAN_TRIP" | jq '.params | length')
        if [ "$PARAMS_COUNT" -eq 2 ]; then
            print_success "plan_trip has 2 params (destination, budget)"
        else
            print_failure "plan_trip should have 2 params, found $PARAMS_COUNT"
        fi

        # Check result (should be ContentDescriptor)
        if echo "$PLAN_TRIP" | jq -e '.result.name' > /dev/null; then
            print_success "plan_trip result is ContentDescriptor"
        else
            print_failure "plan_trip result not ContentDescriptor format"
        fi
    else
        print_failure "plan_trip method not found"
    fi

    # Check quick_search method
    print_test "Validate quick_search method"
    QUICK_SEARCH=$(echo "$INTERFACE_JSON" | jq '.methods[] | select(.name == "quick_search")')

    if [ -n "$QUICK_SEARCH" ]; then
        print_success "quick_search method exists"

        # Check params
        PARAMS_COUNT=$(echo "$QUICK_SEARCH" | jq '.params | length')
        if [ "$PARAMS_COUNT" -eq 1 ]; then
            print_success "quick_search has 1 param (query)"
        else
            print_failure "quick_search should have 1 param, found $PARAMS_COUNT"
        fi

        # Verify auth parameter is NOT exposed
        if echo "$QUICK_SEARCH" | jq -e '.params[] | select(.name == "auth")' > /dev/null; then
            print_failure "auth parameter should not be exposed"
        else
            print_success "auth parameter correctly filtered"
        fi
    else
        print_failure "quick_search method not found"
    fi
}

# Test RPC calls
test_rpc_calls() {
    print_header "Test 3: JSON-RPC 2.0 Calls"

    if [ "$TRAVEL_AGENT_DOWN" = "1" ]; then
        print_info "Skipping - Travel Agent not running"
        return
    fi

    # Test plan_trip
    print_test "Call plan_trip method"
    PLAN_TRIP_RESPONSE=$(curl -sf -X POST "${TRAVEL_BASE_URL}${TRAVEL_PREFIX}/rpc" \
        -H "Content-Type: application/json" \
        -d '{
            "jsonrpc": "2.0",
            "id": "test-1",
            "method": "plan_trip",
            "params": {
                "destination": "Tokyo",
                "budget": 1000
            }
        }')

    if [ -n "$PLAN_TRIP_RESPONSE" ]; then
        print_success "plan_trip response received"

        # Check for result
        if echo "$PLAN_TRIP_RESPONSE" | jq -e '.result' > /dev/null; then
            print_success "plan_trip returned result"

            # Check result fields
            DESTINATION=$(echo "$PLAN_TRIP_RESPONSE" | jq -r '.result.destination')
            BUDGET=$(echo "$PLAN_TRIP_RESPONSE" | jq -r '.result.budget')
            STATUS=$(echo "$PLAN_TRIP_RESPONSE" | jq -r '.result.status')

            print_info "Result: destination=$DESTINATION, budget=$BUDGET, status=$STATUS"

            if [ "$DESTINATION" = "Tokyo" ] && [ "$BUDGET" = "1000" ] && [ "$STATUS" = "planned" ]; then
                print_success "plan_trip result valid"
            else
                print_failure "plan_trip result invalid"
            fi
        else
            print_failure "plan_trip no result field"
        fi
    else
        print_failure "plan_trip call failed"
    fi

    # Test quick_search
    print_test "Call quick_search method"
    QUICK_SEARCH_RESPONSE=$(curl -sf -X POST "${TRAVEL_BASE_URL}${TRAVEL_PREFIX}/rpc" \
        -H "Content-Type: application/json" \
        -d '{
            "jsonrpc": "2.0",
            "id": "test-2",
            "method": "quick_search",
            "params": {
                "query": "Paris"
            }
        }')

    if [ -n "$QUICK_SEARCH_RESPONSE" ]; then
        print_success "quick_search response received"

        if echo "$QUICK_SEARCH_RESPONSE" | jq -e '.result' > /dev/null; then
            print_success "quick_search returned result"

            QUERY=$(echo "$QUICK_SEARCH_RESPONSE" | jq -r '.result.query')
            print_info "Result: query=$QUERY"

            if [ "$QUERY" = "Paris" ]; then
                print_success "quick_search result valid"
            else
                print_failure "quick_search result invalid"
            fi
        else
            print_failure "quick_search no result field"
        fi
    else
        print_failure "quick_search call failed"
    fi
}

# Test error handling
test_error_handling() {
    print_header "Test 4: Error Handling"

    if [ "$TRAVEL_AGENT_DOWN" = "1" ]; then
        print_info "Skipping - Travel Agent not running"
        return
    fi

    print_test "Call with invalid method"
    ERROR_RESPONSE=$(curl -sf -X POST "${TRAVEL_BASE_URL}${TRAVEL_PREFIX}/rpc" \
        -H "Content-Type: application/json" \
        -d '{
            "jsonrpc": "2.0",
            "id": "test-error",
            "method": "nonexistent_method",
            "params": {}
        }')

    if echo "$ERROR_RESPONSE" | jq -e '.error' > /dev/null; then
        ERROR_CODE=$(echo "$ERROR_RESPONSE" | jq -r '.error.code')
        print_success "Error returned correctly (code: $ERROR_CODE)"
    else
        print_failure "Should return error for invalid method"
    fi

    print_test "Call with missing required params"
    ERROR_RESPONSE=$(curl -sf -X POST "${TRAVEL_BASE_URL}${TRAVEL_PREFIX}/rpc" \
        -H "Content-Type: application/json" \
        -d '{
            "jsonrpc": "2.0",
            "id": "test-error-2",
            "method": "plan_trip",
            "params": {}
        }')

    if echo "$ERROR_RESPONSE" | jq -e '.error' > /dev/null; then
        print_success "Error returned for missing params"
    else
        print_failure "Should return error for missing params"
    fi
}

# Print summary
print_summary() {
    print_header "Test Summary"

    TOTAL=$((TESTS_PASSED + TESTS_FAILED))
    echo ""
    echo -e "Total Tests: ${BLUE}$TOTAL${NC}"
    echo -e "Passed:      ${GREEN}$TESTS_PASSED${NC}"
    echo -e "Failed:      ${RED}$TESTS_FAILED${NC}"
    echo ""

    if [ $TESTS_FAILED -eq 0 ]; then
        echo -e "${GREEN}🎉 All tests passed!${NC}"
        exit 0
    else
        echo -e "${RED}❌ Some tests failed${NC}"
        exit 1
    fi
}

# Main execution
main() {
    # Initialize state
    TRAVEL_AGENT_DOWN=0

    echo ""
    echo -e "${BLUE}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║         OpenANP Hybrid Agent Test Suite                   ║${NC}"
    echo -e "${BLUE}╚════════════════════════════════════════════════════════════╝${NC}"

    check_services
    test_ad_json
    test_interface_json
    test_rpc_calls
    test_error_handling
    print_summary
}

# Run tests
main
