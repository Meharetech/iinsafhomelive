#!/usr/bin/env python3
"""
Test script to demonstrate email functionality
"""
import requests
import json

def test_email_api():
    base_url = "http://localhost:5005"
    
    print("Testing Email API...")
    print("=" * 50)
    
    try:
        # Test 1: Send single email
        print("\n1. Testing single email...")
        email_data = {
            "to": "test@example.com",
            "subject": "Test Email from YouTube Live Dashboard",
            "body": "This is a test email from the YouTube Live Dashboard system.",
            "html_body": "<h2>Test Email</h2><p>This is a <strong>test email</strong> from the YouTube Live Dashboard system.</p>"
        }
        
        response = requests.post(f"{base_url}/api/email/send", json=email_data)
        if response.status_code == 200:
            data = response.json()
            print("✓ Single email endpoint working")
            print(f"  - Success: {data.get('success')}")
            print(f"  - Message: {data.get('message')}")
        else:
            print(f"✗ Single email failed: {response.status_code}")
            print(f"  - Response: {response.text}")
        
        # Test 2: Send bulk email
        print("\n2. Testing bulk email...")
        bulk_email_data = {
            "recipients": ["test1@example.com", "test2@example.com"],
            "subject": "Bulk Test Email",
            "body": "This is a bulk test email from the YouTube Live Dashboard system.",
            "html_body": "<h2>Bulk Test Email</h2><p>This is a <strong>bulk test email</strong> from the YouTube Live Dashboard system.</p>"
        }
        
        response = requests.post(f"{base_url}/api/email/send-bulk", json=bulk_email_data)
        if response.status_code == 200:
            data = response.json()
            print("✓ Bulk email endpoint working")
            print(f"  - Success: {data.get('success')}")
            print(f"  - Message: {data.get('message')}")
        else:
            print(f"✗ Bulk email failed: {response.status_code}")
            print(f"  - Response: {response.text}")
        
        # Test 3: Send email to all reporters
        print("\n3. Testing email to all reporters...")
        reporters_email_data = {
            "subject": "Important Update for All Reporters",
            "body": "This is an important update for all reporters in the system.",
            "html_body": """
            <h2>Important Update</h2>
            <p>Dear Reporters,</p>
            <p>This is an important update for all reporters in the system.</p>
            <p>Please review the following information:</p>
            <ul>
                <li>New reporting guidelines</li>
                <li>Updated contact information</li>
                <li>Schedule changes</li>
            </ul>
            <p>Best regards,<br>YouTube Live Dashboard Team</p>
            """
        }
        
        response = requests.post(f"{base_url}/api/email/send-to-reporters", json=reporters_email_data)
        if response.status_code == 200:
            data = response.json()
            print("✓ Email to reporters endpoint working")
            print(f"  - Success: {data.get('success')}")
            print(f"  - Message: {data.get('message')}")
            print(f"  - Recipients: {data.get('recipients_count', 0)}")
        else:
            print(f"✗ Email to reporters failed: {response.status_code}")
            print(f"  - Response: {response.text}")
        
    except requests.exceptions.ConnectionError:
        print("✗ Server not running. Please start the server first with: python app.py")
        return
    except Exception as e:
        print(f"✗ Error: {e}")
        return
    
    print("\n" + "=" * 50)
    print("Email API testing completed!")
    print("\nEmail API Endpoints available:")
    print("- POST /api/email/send - Send single email")
    print("- POST /api/email/send-bulk - Send bulk email")
    print("- POST /api/email/send-to-reporters - Send email to all reporters")

if __name__ == "__main__":
    test_email_api()
