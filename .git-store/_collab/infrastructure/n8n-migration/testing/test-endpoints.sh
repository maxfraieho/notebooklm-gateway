#!/bin/bash
# ============================================
# Garden API Adapter - Endpoint Tests
# ============================================

set -e

# Configuration
API_URL="${API_URL:-http://localhost:3001}"
TOKEN=""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Counters
PASSED=0
FAILED=0

# Helper functions
log_test() {
    echo -e "\n${YELLOW}TEST:${NC} $1"
}

log_pass() {
    echo -e "${GREEN}✓ PASS:${NC} $1"
    ((PASSED++))
}

log_fail() {
    echo -e "${RED}✗ FAIL:${NC} $1"
    ((FAILED++))
}

check_status() {
    local expected=$1
    local actual=$2
    local test_name=$3

    if [ "$actual" -eq "$expected" ]; then
        log_pass "$test_name (status: $actual)"
        return 0
    else
        log_fail "$test_name (expected: $expected, got: $actual)"
        return 1
    fi
}

check_json_field() {
    local json=$1
    local field=$2
    local expected=$3
    local test_name=$4

    local actual=$(echo "$json" | jq -r ".$field")

    if [ "$actual" == "$expected" ]; then
        log_pass "$test_name ($field: $actual)"
        return 0
    else
        log_fail "$test_name (expected $field: $expected, got: $actual)"
        return 1
    fi
}

# ============================================
# Tests
# ============================================

echo "============================================"
echo "Garden API Adapter - Endpoint Tests"
echo "API URL: $API_URL"
echo "============================================"

# 1. Health Check
log_test "GET /health"
RESPONSE=$(curl -s -w "\n%{http_code}" "$API_URL/health")
STATUS=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | sed '$d')

check_status 200 "$STATUS" "Health check status"
check_json_field "$BODY" "status" "ok" "Health check response"

# 2. Auth Status (not initialized)
log_test "POST /auth/status"
RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$API_URL/auth/status")
STATUS=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | sed '$d')

check_status 200 "$STATUS" "Auth status"
check_json_field "$BODY" "success" "true" "Auth status success"

# Check if already initialized
INITIALIZED=$(echo "$BODY" | jq -r '.initialized')

if [ "$INITIALIZED" == "false" ]; then
    # 3. Auth Setup
    log_test "POST /auth/setup"
    RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$API_URL/auth/setup" \
        -H "Content-Type: application/json" \
        -d '{"password":"test123"}')
    STATUS=$(echo "$RESPONSE" | tail -n1)
    BODY=$(echo "$RESPONSE" | sed '$d')

    check_status 200 "$STATUS" "Auth setup"
    check_json_field "$BODY" "success" "true" "Auth setup success"
fi

# 4. Auth Login
log_test "POST /auth/login"
RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$API_URL/auth/login" \
    -H "Content-Type: application/json" \
    -d '{"password":"test123"}')
STATUS=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | sed '$d')

check_status 200 "$STATUS" "Auth login"
check_json_field "$BODY" "success" "true" "Auth login success"

TOKEN=$(echo "$BODY" | jq -r '.token')
if [ "$TOKEN" != "null" ] && [ -n "$TOKEN" ]; then
    log_pass "Got JWT token"
else
    log_fail "No JWT token received"
fi

# 5. Auth Validate
log_test "POST /auth/validate"
RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$API_URL/auth/validate" \
    -H "Content-Type: application/json" \
    -d "{\"token\":\"$TOKEN\"}")
STATUS=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | sed '$d')

check_status 200 "$STATUS" "Auth validate"
check_json_field "$BODY" "valid" "true" "Token is valid"

# 6. Auth Refresh
log_test "POST /auth/refresh"
RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$API_URL/auth/refresh" \
    -H "Authorization: Bearer $TOKEN")
STATUS=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | sed '$d')

check_status 200 "$STATUS" "Auth refresh"
check_json_field "$BODY" "success" "true" "Auth refresh success"

# 7. Zones List (empty)
log_test "GET /zones/list"
RESPONSE=$(curl -s -w "\n%{http_code}" "$API_URL/zones/list" \
    -H "Authorization: Bearer $TOKEN")
STATUS=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | sed '$d')

check_status 200 "$STATUS" "Zones list"
check_json_field "$BODY" "success" "true" "Zones list success"

# 8. Create Zone
log_test "POST /zones/create"
RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$API_URL/zones/create" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $TOKEN" \
    -d '{
        "name": "Test Zone",
        "description": "Test zone for API testing",
        "allowedPaths": ["test/"],
        "ttlMinutes": 60,
        "notes": [
            {"slug": "test/note1", "title": "Test Note", "content": "Hello World", "tags": ["test"]}
        ],
        "accessType": "read"
    }')
STATUS=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | sed '$d')

check_status 200 "$STATUS" "Create zone"
check_json_field "$BODY" "success" "true" "Create zone success"

ZONE_ID=$(echo "$BODY" | jq -r '.zoneId')
ACCESS_CODE=$(echo "$BODY" | jq -r '.accessCode')

if [ "$ZONE_ID" != "null" ] && [ -n "$ZONE_ID" ]; then
    log_pass "Got zone ID: $ZONE_ID"
else
    log_fail "No zone ID received"
fi

# 9. Validate Zone
log_test "GET /zones/validate/:zoneId"
RESPONSE=$(curl -s -w "\n%{http_code}" "$API_URL/zones/validate/$ZONE_ID?code=$ACCESS_CODE")
STATUS=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | sed '$d')

check_status 200 "$STATUS" "Validate zone"
check_json_field "$BODY" "success" "true" "Validate zone success"
check_json_field "$BODY" "id" "$ZONE_ID" "Zone ID matches"

# 10. Get Zone Notes
log_test "GET /zones/:zoneId/notes"
RESPONSE=$(curl -s -w "\n%{http_code}" "$API_URL/zones/$ZONE_ID/notes")
STATUS=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | sed '$d')

check_status 200 "$STATUS" "Get zone notes"
check_json_field "$BODY" "success" "true" "Get zone notes success"

# 11. Invalid Zone Access Code
log_test "GET /zones/validate/:zoneId (invalid code)"
RESPONSE=$(curl -s -w "\n%{http_code}" "$API_URL/zones/validate/$ZONE_ID?code=WRONG-CODE")
STATUS=$(echo "$RESPONSE" | tail -n1)

check_status 403 "$STATUS" "Invalid access code rejected"

# 12. Comments Create
log_test "POST /comments/create"
RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$API_URL/comments/create" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $TOKEN" \
    -d '{
        "articleSlug": "test/article",
        "content": "This is a test comment",
        "authorName": "Test User"
    }')
STATUS=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | sed '$d')

check_status 200 "$STATUS" "Create comment"
check_json_field "$BODY" "success" "true" "Create comment success"

COMMENT_ID=$(echo "$BODY" | jq -r '.comment.id')

# 13. Comments Get
log_test "GET /comments/:articleSlug"
RESPONSE=$(curl -s -w "\n%{http_code}" "$API_URL/comments/test%2Farticle" \
    -H "Authorization: Bearer $TOKEN")
STATUS=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | sed '$d')

check_status 200 "$STATUS" "Get comments"
check_json_field "$BODY" "success" "true" "Get comments success"

# 14. Sessions Create
log_test "POST /sessions/create"
RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$API_URL/sessions/create" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $TOKEN" \
    -d '{
        "folders": ["test/"],
        "ttlMinutes": 30,
        "notes": [
            {"slug": "test/note", "title": "Session Note", "content": "Test", "tags": []}
        ]
    }')
STATUS=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | sed '$d')

check_status 200 "$STATUS" "Create session"
check_json_field "$BODY" "success" "true" "Create session success"

SESSION_ID=$(echo "$BODY" | jq -r '.sessionId')

# 15. MCP Initialize
log_test "POST /mcp (initialize)"
RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$API_URL/mcp?session=$SESSION_ID" \
    -H "Content-Type: application/json" \
    -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}')
STATUS=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | sed '$d')

check_status 200 "$STATUS" "MCP initialize"

JSONRPC=$(echo "$BODY" | jq -r '.jsonrpc')
if [ "$JSONRPC" == "2.0" ]; then
    log_pass "MCP JSON-RPC response valid"
else
    log_fail "MCP JSON-RPC response invalid"
fi

# 16. MCP tools/list
log_test "POST /mcp (tools/list)"
RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$API_URL/mcp?session=$SESSION_ID" \
    -H "Content-Type: application/json" \
    -d '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}')
STATUS=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | sed '$d')

check_status 200 "$STATUS" "MCP tools/list"

TOOLS_COUNT=$(echo "$BODY" | jq '.result.tools | length')
if [ "$TOOLS_COUNT" -gt 0 ]; then
    log_pass "MCP returned $TOOLS_COUNT tools"
else
    log_fail "MCP returned no tools"
fi

# 17. SSE Connection
log_test "GET /sse"
RESPONSE=$(curl -s -m 2 -w "\n%{http_code}" "$API_URL/sse?session=$SESSION_ID" 2>/dev/null || true)
STATUS=$(echo "$RESPONSE" | tail -n1)

# SSE might timeout but should return 200 initially
if [ "$STATUS" == "200" ] || [ -z "$STATUS" ]; then
    log_pass "SSE endpoint accessible"
else
    log_fail "SSE endpoint failed (status: $STATUS)"
fi

# 18. Cleanup - Delete Comment
log_test "DELETE /comments/:commentId"
RESPONSE=$(curl -s -w "\n%{http_code}" -X DELETE "$API_URL/comments/$COMMENT_ID" \
    -H "Authorization: Bearer $TOKEN")
STATUS=$(echo "$RESPONSE" | tail -n1)

check_status 200 "$STATUS" "Delete comment"

# 19. Cleanup - Delete Zone
log_test "DELETE /zones/:zoneId"
RESPONSE=$(curl -s -w "\n%{http_code}" -X DELETE "$API_URL/zones/$ZONE_ID" \
    -H "Authorization: Bearer $TOKEN")
STATUS=$(echo "$RESPONSE" | tail -n1)

check_status 200 "$STATUS" "Delete zone"

# 20. Unauthorized Access
log_test "GET /zones/list (no auth)"
RESPONSE=$(curl -s -w "\n%{http_code}" "$API_URL/zones/list")
STATUS=$(echo "$RESPONSE" | tail -n1)

check_status 401 "$STATUS" "Unauthorized access rejected"

# ============================================
# Summary
# ============================================

echo ""
echo "============================================"
echo "TEST SUMMARY"
echo "============================================"
echo -e "${GREEN}Passed:${NC} $PASSED"
echo -e "${RED}Failed:${NC} $FAILED"
echo "Total: $((PASSED + FAILED))"
echo "============================================"

if [ "$FAILED" -gt 0 ]; then
    exit 1
fi
