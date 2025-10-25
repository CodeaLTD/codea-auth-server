#!/usr/bin/env python3
"""
Simple test script for Google OAuth authentication.
Run this after setting up your Google Cloud Console credentials.
"""

import requests
import json
import webbrowser
from urllib.parse import urlparse, parse_qs

# Base URL for your Django server
BASE_URL = "http://localhost:8000"

def test_google_auth_status():
    """Test if Google OAuth is properly configured."""
    print("🔍 Testing Google OAuth status...")
    
    try:
        response = requests.get(f"{BASE_URL}/api/auth/google/status/")
        if response.status_code == 200:
            data = response.json()
            print("✅ Google OAuth Status:")
            print(f"   Status: {data['status']}")
            print(f"   Client ID configured: {data['client_id_configured']}")
            print(f"   Google services accessible: {data['google_services_accessible']}")
            return data['status'] == 'active'
        else:
            print(f"❌ Status check failed: {response.status_code}")
            return False
    except requests.exceptions.ConnectionError:
        print("❌ Cannot connect to Django server. Make sure it's running on localhost:8000")
        return False
    except Exception as e:
        print(f"❌ Error: {e}")
        return False

def test_google_auth_url():
    """Test Google OAuth URL generation."""
    print("\n🔗 Testing Google OAuth URL generation...")
    
    try:
        response = requests.get(f"{BASE_URL}/api/auth/google/url/")
        if response.status_code == 200:
            data = response.json()
            print("✅ Google OAuth URL generated:")
            print(f"   URL: {data['auth_url']}")
            print(f"   State: {data['state']}")
            return data['auth_url']
        else:
            print(f"❌ URL generation failed: {response.status_code}")
            return None
    except Exception as e:
        print(f"❌ Error: {e}")
        return None

def test_google_auth_config():
    """Test Google OAuth configuration endpoint."""
    print("\n⚙️ Testing Google OAuth configuration...")
    
    try:
        response = requests.get(f"{BASE_URL}/api/auth/google/config/")
        if response.status_code == 200:
            data = response.json()
            print("✅ Google OAuth Configuration:")
            print(f"   Client ID: {data['client_id']}")
            print(f"   Redirect URI: {data['redirect_uri']}")
            print(f"   Scope: {data['scope']}")
            return True
        else:
            print(f"❌ Config retrieval failed: {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ Error: {e}")
        return False

def open_google_auth_in_browser():
    """Open Google OAuth URL in browser for manual testing."""
    print("\n🌐 Opening Google OAuth in browser...")
    
    auth_url = test_google_auth_url()
    if auth_url:
        print("📱 Please complete the Google OAuth flow in your browser.")
        print("   After authentication, you'll be redirected to a callback URL.")
        print("   Copy the 'code' parameter from the URL and use it to test the callback.")
        
        try:
            webbrowser.open(auth_url)
            print("✅ Browser opened with Google OAuth URL")
        except Exception as e:
            print(f"❌ Could not open browser: {e}")
            print(f"   Please manually visit: {auth_url}")

def test_google_auth_callback(code):
    """Test Google OAuth callback with authorization code."""
    print(f"\n🔄 Testing Google OAuth callback with code: {code[:20]}...")
    
    try:
        payload = {
            "code": code,
            "state": "test_state"
        }
        
        response = requests.post(
            f"{BASE_URL}/api/auth/google/callback/",
            json=payload,
            headers={'Content-Type': 'application/json'}
        )
        
        if response.status_code == 200:
            data = response.json()
            print("✅ Google OAuth callback successful!")
            print(f"   User: {data['user']['email']}")
            print(f"   New user: {data['is_new_user']}")
            print(f"   Access token: {data['access'][:50]}...")
            return True
        else:
            print(f"❌ Callback failed: {response.status_code}")
            print(f"   Response: {response.text}")
            return False
    except Exception as e:
        print(f"❌ Error: {e}")
        return False

def main():
    """Main test function."""
    print("🚀 Google OAuth Authentication Test")
    print("=" * 50)
    
    # Test 1: Check status
    if not test_google_auth_status():
        print("\n❌ Google OAuth is not properly configured.")
        print("   Please update your settings.py with actual Google OAuth credentials.")
        return
    
    # Test 2: Check configuration
    test_google_auth_config()
    
    # Test 3: Generate auth URL
    auth_url = test_google_auth_url()
    if not auth_url:
        print("\n❌ Could not generate Google OAuth URL.")
        return
    
    # Test 4: Open in browser for manual testing
    print("\n" + "=" * 50)
    print("📋 Manual Testing Instructions:")
    print("1. Complete the Google OAuth flow in your browser")
    print("2. After authentication, you'll be redirected to a callback URL")
    print("3. Copy the 'code' parameter from the URL")
    print("4. Run this script again with the code: python test_google_auth.py <code>")
    print("=" * 50)
    
    open_google_auth_in_browser()
    
    # If code provided as argument, test callback
    import sys
    if len(sys.argv) > 1:
        code = sys.argv[1]
        test_google_auth_callback(code)

if __name__ == "__main__":
    main()
