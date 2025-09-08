# Email API Documentation

## Overview
The YouTube Live Dashboard now includes comprehensive email functionality using Flask-Mail with Gmail SMTP. You can send emails to individual recipients, multiple recipients, or all reporters in the system.

## Configuration
- **SMTP Server:** smtp.gmail.com
- **Port:** 587 (TLS)
- **Email:** iinsaftest@gmail.com
- **App Password:** clstvanemhrttcio

## API Endpoints

### 1. Send Single Email
**Endpoint:** `POST /api/email/send`  
**Authentication:** Not Required (Public)  
**Description:** Send email to a single recipient.

**Request Body:**
```json
{
  "to": "recipient@example.com",
  "subject": "Email Subject",
  "body": "Plain text email body",
  "html_body": "<h2>HTML Email Body</h2><p>This is HTML content</p>"
}
```

**Response:**
```json
{
  "success": true,
  "message": "Email sent successfully"
}
```

### 2. Send Bulk Email
**Endpoint:** `POST /api/email/send-bulk`  
**Authentication:** Not Required (Public)  
**Description:** Send email to multiple recipients.

**Request Body:**
```json
{
  "recipients": ["email1@example.com", "email2@example.com"],
  "subject": "Bulk Email Subject",
  "body": "Plain text email body",
  "html_body": "<h2>HTML Email Body</h2><p>This is HTML content</p>"
}
```

**Response:**
```json
{
  "success": true,
  "message": "Email sent successfully to 2 recipients"
}
```

### 3. Send Email to All Reporters
**Endpoint:** `POST /api/email/send-to-reporters`  
**Authentication:** Not Required (Public)  
**Description:** Send email to all reporters from the API.

**Request Body:**
```json
{
  "subject": "Important Update for Reporters",
  "body": "Plain text email body",
  "html_body": "<h2>Important Update</h2><p>This is HTML content</p>"
}
```

**Response:**
```json
{
  "success": true,
  "message": "Email sent successfully to 6 recipients",
  "recipients_count": 6
}
```

## Usage Examples

### JavaScript/Frontend

#### Send Single Email
```javascript
async function sendEmail() {
  try {
    const response = await fetch('/api/email/send', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        to: 'user@example.com',
        subject: 'Test Email',
        body: 'This is a test email',
        html_body: '<h2>Test Email</h2><p>This is a test email</p>'
      })
    });
    
    const data = await response.json();
    if (data.success) {
      console.log('Email sent successfully');
    } else {
      console.error('Failed to send email:', data.message);
    }
  } catch (error) {
    console.error('Error:', error);
  }
}
```

#### Send Email to All Reporters
```javascript
async function emailAllReporters() {
  try {
    const response = await fetch('/api/email/send-to-reporters', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        subject: 'Important Update',
        body: 'This is an important update for all reporters.',
        html_body: `
          <h2>Important Update</h2>
          <p>Dear Reporters,</p>
          <p>This is an important update for all reporters.</p>
          <p>Best regards,<br>YouTube Live Dashboard Team</p>
        `
      })
    });
    
    const data = await response.json();
    if (data.success) {
      console.log(`Email sent to ${data.recipients_count} reporters`);
    } else {
      console.error('Failed to send email:', data.message);
    }
  } catch (error) {
    console.error('Error:', error);
  }
}
```

### Python

#### Send Single Email
```python
import requests

def send_email():
    url = "http://localhost:5005/api/email/send"
    data = {
        "to": "user@example.com",
        "subject": "Test Email",
        "body": "This is a test email",
        "html_body": "<h2>Test Email</h2><p>This is a test email</p>"
    }
    
    response = requests.post(url, json=data)
    result = response.json()
    
    if result['success']:
        print("Email sent successfully")
    else:
        print(f"Failed to send email: {result['message']}")

send_email()
```

#### Send Email to All Reporters
```python
import requests

def email_all_reporters():
    url = "http://localhost:5005/api/email/send-to-reporters"
    data = {
        "subject": "Important Update",
        "body": "This is an important update for all reporters.",
        "html_body": """
        <h2>Important Update</h2>
        <p>Dear Reporters,</p>
        <p>This is an important update for all reporters.</p>
        <p>Best regards,<br>YouTube Live Dashboard Team</p>
        """
    }
    
    response = requests.post(url, json=data)
    result = response.json()
    
    if result['success']:
        print(f"Email sent to {result['recipients_count']} reporters")
    else:
        print(f"Failed to send email: {result['message']}")

email_all_reporters()
```

### cURL Examples

#### Send Single Email
```bash
curl -X POST "http://localhost:5005/api/email/send" \
  -H "Content-Type: application/json" \
  -d '{
    "to": "user@example.com",
    "subject": "Test Email",
    "body": "This is a test email",
    "html_body": "<h2>Test Email</h2><p>This is a test email</p>"
  }'
```

#### Send Email to All Reporters
```bash
curl -X POST "http://localhost:5005/api/email/send-to-reporters" \
  -H "Content-Type: application/json" \
  -d '{
    "subject": "Important Update",
    "body": "This is an important update for all reporters.",
    "html_body": "<h2>Important Update</h2><p>This is an important update for all reporters.</p>"
  }'
```

## Installation

1. **Install Dependencies:**
   ```bash
   python install_dependencies.py
   ```

2. **Start Server:**
   ```bash
   python app.py
   ```

3. **Test Email Functionality:**
   ```bash
   python test_email.py
   ```

## Error Handling

### Common Errors
- **Invalid Email Address:** Check email format
- **SMTP Authentication Failed:** Verify email credentials
- **Network Error:** Check internet connection
- **No Recipients:** Ensure valid email addresses

### Error Response Format
```json
{
  "success": false,
  "error": "Error message description"
}
```

## Security Notes

- Email credentials are configured in the application
- Use app passwords for Gmail (not regular passwords)
- Consider using environment variables for production
- Rate limiting may be needed for production use

## Testing

Run the test script to verify email functionality:
```bash
python test_email.py
```

This will test all three email endpoints and show the results.
