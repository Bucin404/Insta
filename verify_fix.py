#!/usr/bin/env python3
"""
Verification script to check if the correct session management fix is applied.
Run this to verify you're using the fixed version.
"""

import sys
import os

def check_version():
    """Check if the session management fix is applied"""
    
    print("🔍 Checking session management fix...")
    print("=" * 60)
    
    # Check if main.py exists
    if not os.path.exists('main.py'):
        print("❌ ERROR: main.py not found in current directory")
        print("   Please run this script from the repository root")
        return False
    
    with open('main.py', 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Check for old code (should NOT exist)
    old_patterns = [
        "♻️   Reusing session",
        "🔄  Forced session rotation",
        "smart session strategy",
        "session_success_count",
        "session_checkpoint_count",
        "consecutive_checkpoints"
    ]
    
    # Check for new code (should exist)
    new_patterns = [
        "🆕  Creating NEW session for account",
        "CRITICAL FIX: Create NEW session for EVERY account",
        "One session per account",
        "_destroy_session_completely"
    ]
    
    errors = []
    warnings = []
    
    # Check for old code
    for pattern in old_patterns:
        if pattern in content:
            errors.append(f"❌ Found OLD code: '{pattern}'")
    
    # Check for new code
    for pattern in new_patterns:
        if pattern not in content:
            warnings.append(f"⚠️  Missing NEW code: '{pattern}'")
    
    # Results
    print("\n📊 VERIFICATION RESULTS:")
    print("=" * 60)
    
    if errors:
        print("\n❌ FAILED - Old code detected:")
        for error in errors:
            print(f"   {error}")
        print("\n   Your code is NOT fixed. You need to:")
        print("   1. git fetch origin")
        print("   2. git checkout copilot/fix-session-handling-and-ip-generation")
        print("   3. git pull origin copilot/fix-session-handling-and-ip-generation")
        print("   4. rm -rf __pycache__ *.pyc  # Clear Python cache")
        print("   5. Restart your application")
        return False
    
    if warnings:
        print("\n⚠️  WARNINGS:")
        for warning in warnings:
            print(f"   {warning}")
    
    if not errors and not warnings:
        print("\n✅ SUCCESS - Session management fix is applied correctly!")
        print("\n   What you should see when running:")
        print("   - '🆕 Creating NEW session for account X (no reuse)'")
        print("   - NO MORE '♻️ Reusing session' messages")
        print("   - Every account gets a fresh session")
        print("\n   If you still see old messages, try:")
        print("   1. Stop your application completely")
        print("   2. rm -rf __pycache__ *.pyc  # Clear Python cache")
        print("   3. Restart your application")
        return True
    
    if not errors and warnings:
        print("\n⚠️  PARTIAL - Some new code missing, but no old code found")
        print("   The fix might be partially applied.")
        return True
    
    return False

if __name__ == "__main__":
    success = check_version()
    sys.exit(0 if success else 1)
