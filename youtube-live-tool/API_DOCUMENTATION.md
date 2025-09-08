# YouTube Live Dashboard - Complete API Documentation

## Overview
The YouTube Live Dashboard provides a comprehensive API for managing live streaming across multiple YouTube channels. This API allows you to monitor live streams, track viewer counts, and manage channel operations in real-time.

## Base URL
```
http://localhost:5005
```

## Authentication
**Public API Endpoints:** The live streaming API endpoints are publicly accessible and do not require authentication.

**Admin Endpoints:** Some endpoints still require authentication for security:
- Dashboard management (`/`, `/switch_account`, etc.)
- Stream creation and management
- Channel deletion

**Public Endpoints:**
- Channel authorization (`/authorize`) - Anyone can add/authorize channels
- OAuth callbacks (`/oauth2callback`, `/authorize_oauth`)

**Login Endpoint (for admin functions):**
```http
POST /login
Content-Type: application/json

{
  "username": "user",
  "password": "1234567890"
}
```

## API Endpoints

### 1. Live Streaming Status

#### Get Overall Live Status
**Endpoint:** `GET /api/live/status`  
**Authentication:** Not Required (Public)  
**Description:** Get comprehensive live streaming status including all channels, viewer counts, and URLs.

**Response:**
```json
{
  "success": true,
  "is_live": true,
  "total_viewers": 150,
  "live_channels": [
    {
      "channel_id": "UCImw27DBFWp6VLU9Joi4ZIA",
      "broadcast_id": "abc123",
      "title": "My Live Stream",
      "viewers": 75,
      "live_url": "https://www.youtube.com/watch?v=abc123",
      "status": "live"
    }
  ],
  "total_channels": 1
}
```

**Error Response:**
```json
{
  "success": false,
  "error": "Error message description"
}
```

---

### 2. Channel Management

#### Get Live Channel URLs
**Endpoint:** `GET /api/live/channels`  
**Authentication:** Not Required (Public)  
**Description:** Get all live channel URLs and basic information.

**Response:**
```json
{
  "success": true,
  "live_channels": [
    {
      "channel_id": "UCImw27DBFWp6VLU9Joi4ZIA",
      "broadcast_id": "abc123",
      "title": "My Live Stream",
      "live_url": "https://www.youtube.com/watch?v=abc123",
      "status": "live"
    }
  ],
  "count": 1
}
```

---

#### Get Specific Channel Details
**Endpoint:** `GET /api/live/channel/<channel_id>`  
**Authentication:** Not Required (Public)  
**Description:** Get detailed information for a specific channel.

**Parameters:**
- `channel_id` (string): YouTube channel ID

**Response:**
```json
{
  "success": true,
  "channel_id": "UCImw27DBFWp6VLU9Joi4ZIA",
  "broadcast_id": "abc123",
  "title": "My Live Stream",
  "description": "Stream description",
  "status": "live",
  "privacy_status": "public",
  "viewers": 75,
  "live_url": "https://www.youtube.com/watch?v=abc123",
  "scheduled_start": "2025-09-08T10:00:00Z",
  "actual_start": "2025-09-08T10:05:00Z",
  "scheduled_end": "2025-09-08T12:00:00Z",
  "actual_end": null,
  "is_live": true
}
```

---

### 3. Viewer Analytics

#### Get Viewer Counts
**Endpoint:** `GET /api/live/viewers`  
**Authentication:** Not Required (Public)  
**Description:** Get real-time viewer counts for all channels.

**Response:**
```json
{
  "success": true,
  "viewer_data": {
    "UCImw27DBFWp6VLU9Joi4ZIA": {
      "viewers": 75,
      "status": "live"
    }
  },
  "total_viewers": 75,
  "live_channels": 1
}
```

---

### 4. Legacy Endpoints

#### Multi-Instant Viewers (Legacy)
**Endpoint:** `GET /multi_instant_viewers`  
**Authentication:** Not Required  
**Description:** Legacy endpoint for backward compatibility. Returns viewer counts for all channels.

**Response:**
```json
{
  "UCImw27DBFWp6VLU9Joi4ZIA": 75,
  "UCAnotherChannelID": 0
}
```

---

## Usage Examples

### JavaScript/Frontend

#### Get Live Status
```javascript
async function getLiveStatus() {
  try {
    const response = await fetch('/api/live/status');
    const data = await response.json();
    
    if (data.success) {
      console.log(`Live: ${data.is_live}`);
      console.log(`Total viewers: ${data.total_viewers}`);
      console.log(`Live channels: ${data.live_channels.length}`);
      
      data.live_channels.forEach(channel => {
        console.log(`${channel.title}: ${channel.viewers} viewers`);
        console.log(`URL: ${channel.live_url}`);
      });
    } else {
      console.error('Error:', data.error);
    }
  } catch (error) {
    console.error('Network error:', error);
  }
}

// No authentication required - works directly!
getLiveStatus();
```

#### Real-time Viewer Monitoring
```javascript
async function monitorViewers() {
  try {
    const response = await fetch('/api/live/viewers');
    const data = await response.json();
    
    if (data.success) {
      console.log(`Total viewers: ${data.total_viewers}`);
      console.log(`Live channels: ${data.live_channels}`);
      
      Object.entries(data.viewer_data).forEach(([channelId, info]) => {
        console.log(`${channelId}: ${info.viewers} viewers (${info.status})`);
      });
    }
  } catch (error) {
    console.error('Error monitoring viewers:', error);
  }
}

// Poll every 5 seconds
setInterval(monitorViewers, 5000);
```

#### Get Channel URLs
```javascript
async function getChannelUrls() {
  try {
    const response = await fetch('/api/live/channels');
    const data = await response.json();
    
    if (data.success) {
      console.log(`Found ${data.count} live channels:`);
      data.live_channels.forEach(channel => {
        console.log(`${channel.title}: ${channel.live_url}`);
      });
    }
  } catch (error) {
    console.error('Error getting channels:', error);
  }
}
```

### Python

#### Complete API Client
```python
import requests
import json
import time

class YouTubeLiveAPI:
    def __init__(self, base_url="http://localhost:5005"):
        self.base_url = base_url
        self.session = requests.Session()
    
    def get_live_status(self):
        """Get overall live status"""
        try:
            response = self.session.get(f"{self.base_url}/api/live/status")
            if response.status_code == 200:
                return response.json()
            else:
                print(f"Error: {response.status_code}")
                return None
        except Exception as e:
            print(f"Error: {e}")
            return None
    
    def get_viewers(self):
        """Get viewer counts"""
        try:
            response = self.session.get(f"{self.base_url}/api/live/viewers")
            if response.status_code == 200:
                return response.json()
            else:
                print(f"Error: {response.status_code}")
                return None
        except Exception as e:
            print(f"Error: {e}")
            return None
    
    def get_channels(self):
        """Get live channels"""
        try:
            response = self.session.get(f"{self.base_url}/api/live/channels")
            if response.status_code == 200:
                return response.json()
            else:
                print(f"Error: {response.status_code}")
                return None
        except Exception as e:
            print(f"Error: {e}")
            return None
    
    def get_channel_details(self, channel_id):
        """Get specific channel details"""
        try:
            response = self.session.get(f"{self.base_url}/api/live/channel/{channel_id}")
            if response.status_code == 200:
                return response.json()
            else:
                print(f"Error: {response.status_code}")
                return None
        except Exception as e:
            print(f"Error: {e}")
            return None

# Usage example - No authentication required!
if __name__ == "__main__":
    api = YouTubeLiveAPI()
    
    # Get live status
    status = api.get_live_status()
    if status and status.get('success'):
        print(f"Live: {status['is_live']}")
        print(f"Total viewers: {status['total_viewers']}")
    
    # Get viewers
    viewers = api.get_viewers()
    if viewers and viewers.get('success'):
        print(f"Total viewers: {viewers['total_viewers']}")
    
    # Get channels
    channels = api.get_channels()
    if channels and channels.get('success'):
        print(f"Live channels: {channels['count']}")
```

### cURL Examples

#### Get Live Status
```bash
curl -X GET "http://localhost:5005/api/live/status"
```

#### Get Viewer Counts
```bash
curl -X GET "http://localhost:5005/api/live/viewers"
```

#### Get Channel Details
```bash
curl -X GET "http://localhost:5005/api/live/channel/UCImw27DBFWp6VLU9Joi4ZIA"
```

---

## Error Handling

### HTTP Status Codes
- `200` - Success
- `401` - Unauthorized (not logged in)
- `404` - Channel not found
- `500` - Internal server error

### Error Response Format
```json
{
  "success": false,
  "error": "Error message description"
}
```

### Common Errors
- **Authentication Required**: Make sure you're logged in
- **Channel Not Found**: Channel ID doesn't exist or no active broadcast
- **No Active Broadcast**: Channel is not currently streaming
- **API Rate Limit**: YouTube API has rate limits

---

## Rate Limiting & Performance

### YouTube API Limits
- YouTube Data API v3 has quota limits
- Consider implementing caching for high-frequency requests
- Batch requests when possible

### Recommended Polling Intervals
- **Viewer counts**: 5-10 seconds
- **Channel status**: 10-30 seconds
- **Detailed channel info**: 30-60 seconds

---

## WebSocket Integration (Future)

For real-time updates, consider implementing WebSocket connections:

```javascript
// Future WebSocket implementation
const ws = new WebSocket('ws://localhost:5005/ws/live');
ws.onmessage = function(event) {
  const data = JSON.parse(event.data);
  console.log('Live update:', data);
};
```

---

## CORS Support

The API now includes full CORS (Cross-Origin Resource Sharing) support, allowing web applications from any domain to access the API endpoints.

### CORS Headers
All API responses include the following headers:
- `Access-Control-Allow-Origin: *`
- `Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS`
- `Access-Control-Allow-Headers: Content-Type, Authorization`

### Installation
Install required dependencies:
```bash
# Install dependencies
python install_dependencies.py

# Or manually:
pip install Flask==2.3.3 Flask-CORS==4.0.0 google-auth==2.23.4 google-auth-oauthlib==1.1.0 google-auth-httplib2==0.1.1 google-api-python-client==2.108.0
```

## Testing

### Test Script
Run the included test script to verify API functionality:

```bash
python test_api.py
```

### Manual Testing
1. Install dependencies: `python install_dependencies.py`
2. Start the server: `python app.py`
3. Login at: `http://localhost:5005/login`
4. Test endpoints using the examples above

---

## Support

For issues or questions:
1. Check the error messages in API responses
2. Verify authentication status
3. Ensure YouTube channels are properly configured
4. Check server logs for detailed error information

---

## Changelog

### Version 1.0.0
- Initial API release
- Live status monitoring
- Viewer count tracking
- Channel URL management
- Comprehensive documentation