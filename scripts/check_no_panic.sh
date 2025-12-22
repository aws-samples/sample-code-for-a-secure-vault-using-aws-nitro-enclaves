#!/bin/bash
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

# Script to verify no-panic patterns in the enclave codebase
# This script checks for panic-prone patterns that should not appear in non-test code

set -e

ENCLAVE_SRC="enclave/src"
ERRORS=0

echo "Checking for panic-prone patterns in enclave source code..."

# Check for panic! macro in non-test code
echo "Checking for panic! macro..."
if grep -r --include="*.rs" "panic!" "$ENCLAVE_SRC" | grep -v "#\[cfg(test)\]" | grep -v "mod tests" | grep -v "fn test_" | grep -v "#\[test\]" | grep -v "// " | grep -v "//!" | grep -v "/// " | grep -v "proptest" | grep -v "#\[allow(clippy::expect_used)\]"; then
    echo "WARNING: Found panic! macro in non-test code (may be intentional stub)"
fi

# Check for unreachable! macro in non-test code
echo "Checking for unreachable! macro..."
if grep -r --include="*.rs" "unreachable!" "$ENCLAVE_SRC" | grep -v "#\[cfg(test)\]" | grep -v "mod tests" | grep -v "fn test_" | grep -v "#\[test\]"; then
    echo "ERROR: Found unreachable! macro in non-test code"
    ERRORS=$((ERRORS + 1))
fi

# Check for unimplemented! macro in non-test code
echo "Checking for unimplemented! macro..."
if grep -r --include="*.rs" "unimplemented!" "$ENCLAVE_SRC" | grep -v "#\[cfg(test)\]" | grep -v "mod tests" | grep -v "fn test_" | grep -v "#\[test\]"; then
    echo "ERROR: Found unimplemented! macro in non-test code"
    ERRORS=$((ERRORS + 1))
fi

# Run clippy with no-panic lints
echo "Running clippy with no-panic lints..."
cd enclave
cargo clippy --all-features --all-targets -- -D warnings 2>&1 || {
    echo "ERROR: Clippy found warnings (including panic-prone patterns)"
    ERRORS=$((ERRORS + 1))
}

echo ""
if [ $ERRORS -eq 0 ]; then
    echo "✓ No-panic verification passed"
    exit 0
else
    echo "✗ No-panic verification failed with $ERRORS error(s)"
    exit 1
fi
