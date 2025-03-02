#!/bin/bash

BIN="./ipk-l4-scan"

echo "🔍 Testing program behavior..."

test_case() {
    local desc="$1"
    local cmd="$2"
    local expected="$3"

    echo -n "🟡 $desc ... "
    output=$($cmd 2>&1)

    if echo "$output" | grep -q "$expected"; then
        echo "✅ PASSED"
    else
        echo "❌ FAILED"
        echo "   Command: $cmd"
        echo "   Expected: $expected"
        echo "   Got:"
        echo "$output"
    fi
}

# Test cases
test_case "No parameters -> should list interfaces" \
    "$BIN" \
    "Available network interfaces"

test_case "-i -> should list interfaces" \
    "$BIN -i" \
    "Available network interfaces"

test_case "-i eth0 (without ports or domain) -> should fail" \
    "$BIN -i eth0" \
    "Error: No ports specified"

test_case "-u 20 (without interface or domain) -> should fail" \
    "$BIN -u 20" \
    "Error: No interface specified"

test_case "-i eth0 --pu 20 127.0.0.1 www.vut.cz (too many domains) -> should fail" \
    "$BIN -i eth0 --pu 20 127.0.0.1 www.vut.cz" \
    "Error: Too many targets specified"

test_case "-i eth0 -w -t 20 localhost (missing -w argument) -> should fail" \
    "$BIN -i eth0 -w -t 20 localhost" \
    "Error: -w requires a timeout value"

test_case "-i eth0 -u 20 localhost -> should pass" \
    "$BIN -i eth0 -u 20 localhost" \
    "Scanning target: localhost on interface: eth0"

test_case "-i eth0 -w 10 --pu 20 localhost -> should pass" \
    "$BIN -i eth0 -w 10 --pu 20 localhost" \
    "Scanning target: localhost on interface: eth0"

test_case "-i eth0 -w -t 20 localhost (missing -w argument) -> should fail" \
    "$BIN -i eth0 -w -t 20 localhost" \
    "Error: -w requires a timeout value"

test_case "-i eth0 -t 20 localhost -> should pass" \
    "$BIN -i eth0 -t 20 localhost" \
    "Scanning target: localhost on interface: eth0"

test_case "-i eth0 -w 10 -t 20 localhost -> should pass" \
    "$BIN -i eth0 -w 10 -t 20 localhost" \
    "Scanning target: localhost on interface: eth0"

# New tests for -w
test_case "-i eth0 -w adb (invalid timeout) -> should fail" \
    "$BIN -i eth0 -w adb --pt 80,443,8080 www.vutbr.cz" \
    "Error: Invalid timeout value 'adb'. It must be a positive integer."

test_case "-i eth0 -w -5000 (negative timeout) -> should fail" \
    "$BIN -i eth0 -w -5000 --pt 80,443,8080 www.vutbr.cz" \
    "Error: Invalid timeout value '-5000'. It must be a positive integer."

test_case "-i eth0 -w 5000 (valid timeout) -> should pass" \
    "$BIN -i eth0 -w 5000 --pt 80,443,8080 www.vutbr.cz" \
    "Timeout set to: 5000 ms"

echo "✅ All tests completed!"
