#!/usr/bin/env python3
"""
Test script to demonstrate the live streaming API endpoints
"""
import requests
import json
import time

def test_live_api():
    base_url = "http://localhost:5005"
    
    print("Testing YouTube Live Dashboard API...")
    print("=" * 50)
    print("Note: API endpoints are now PUBLIC - no authentication required!")
    print("=" * 50)
    
    try:
        
        # Test 1: Get live status
        print("\n1. Testing /api/live/status...")
        try:
            response = requests.get(f"{base_url}/api/live/status")
            if response.status_code == 200:
                data = response.json()
                print("✓ Live status endpoint working")
                print(f"  - Live: {data.get('is_live', False)}")
                print(f"  - Total viewers: {data.get('total_viewers', 0)}")
                print(f"  - Live channels: {data.get('total_channels', 0)}")
            else:
                print(f"✗ Status endpoint failed: {response.status_code}")
        except Exception as e:
            print(f"✗ Error testing status: {e}")
        
        # Test 2: Get live channels
        print("\n2. Testing /api/live/channels...")
        try:
            response = requests.get(f"{base_url}/api/live/channels")
            if response.status_code == 200:
                data = response.json()
                print("✓ Live channels endpoint working")
                print(f"  - Channels count: {data.get('count', 0)}")
                for channel in data.get('live_channels', []):
                    print(f"  - {channel['channel_id']}: {channel['live_url']}")
            else:
                print(f"✗ Channels endpoint failed: {response.status_code}")
        except Exception as e:
            print(f"✗ Error testing channels: {e}")
        
        # Test 3: Get viewer counts
        print("\n3. Testing /api/live/viewers...")
        try:
            response = requests.get(f"{base_url}/api/live/viewers")
            if response.status_code == 200:
                data = response.json()
                print("✓ Viewers endpoint working")
                print(f"  - Total viewers: {data.get('total_viewers', 0)}")
                print(f"  - Live channels: {data.get('live_channels', 0)}")
                for channel_id, info in data.get('viewer_data', {}).items():
                    print(f"  - {channel_id}: {info['viewers']} viewers ({info['status']})")
            else:
                print(f"✗ Viewers endpoint failed: {response.status_code}")
        except Exception as e:
            print(f"✗ Error testing viewers: {e}")
        
        # Test 4: Get specific channel details (if any channels exist)
        print("\n4. Testing /api/live/channel/<channel_id>...")
        try:
            # First get channels to find a channel ID
            channels_response = requests.get(f"{base_url}/api/live/channels")
            if channels_response.status_code == 200:
                channels_data = channels_response.json()
                if channels_data.get('live_channels'):
                    channel_id = channels_data['live_channels'][0]['channel_id']
                    
                    response = requests.get(f"{base_url}/api/live/channel/{channel_id}")
                    if response.status_code == 200:
                        data = response.json()
                        print("✓ Channel details endpoint working")
                        print(f"  - Channel: {data.get('channel_id')}")
                        print(f"  - Title: {data.get('title')}")
                        print(f"  - Viewers: {data.get('viewers')}")
                        print(f"  - Status: {data.get('status')}")
                        print(f"  - Live URL: {data.get('live_url')}")
                    else:
                        print(f"✗ Channel details failed: {response.status_code}")
                else:
                    print("  - No live channels to test with")
            else:
                print("  - Could not get channels list")
        except Exception as e:
            print(f"✗ Error testing channel details: {e}")
        
        # Test 5: Real-time monitoring simulation
        print("\n5. Simulating real-time monitoring...")
        print("  (Polling every 3 seconds for 15 seconds)")
        
        for i in range(5):
            try:
                response = requests.get(f"{base_url}/api/live/viewers")
                if response.status_code == 200:
                    data = response.json()
                    print(f"  Poll {i+1}: {data.get('total_viewers', 0)} total viewers")
                else:
                    print(f"  Poll {i+1}: Error {response.status_code}")
            except Exception as e:
                print(f"  Poll {i+1}: Error {e}")
            
            if i < 4:  # Don't sleep after last poll
                time.sleep(3)
        
    except requests.exceptions.ConnectionError:
        print("✗ Server not running. Please start the server first with: python app.py")
        return
    except Exception as e:
        print(f"✗ Error: {e}")
        return
    
    print("\n" + "=" * 50)
    print("API testing completed!")
    print("\nAPI Endpoints available:")
    print("- GET /api/live/status - Overall live status")
    print("- GET /api/live/channels - Live channel URLs")
    print("- GET /api/live/viewers - Viewer counts")
    print("- GET /api/live/channel/<id> - Specific channel details")

if __name__ == "__main__":
    test_live_api()
