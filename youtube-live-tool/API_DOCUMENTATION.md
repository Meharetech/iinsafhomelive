# YouTube Live Dashboard - API Documentation

## Live Streaming API Endpoints

### 1. Get Overall Live Status
**Endpoint:** `GET /api/live/status`  
**Authentication:** Required (Login)  
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

### 2. Get Live Channel URLs
**Endpoint:** `GET /api/live/channels`  
**Authentication:** Required (Login)  
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

### 3. Get Viewer Counts
**Endpoint:** `GET /api/live/viewers`  
**Authentication:** Required (Login)  
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

### 4. Get Specific Channel Details
**Endpoint:** `GET /api/live/channel/<channel_id>`  
**Authentication:** Required (Login)  
**Description:** Get detailed information for a specific channel.

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

## Usage Examples

### JavaScript/Frontend
```javascript
// Get live status
fetch('/api/live/status')
  .then(response => response.json())
  .then(data => {
    if (data.success) {
      console.log(`Live: ${data.is_live}`);
      console.log(`Total viewers: ${data.total_viewers}`);
      console.log(`Live channels: ${data.live_channels.length}`);
    }
  });

// Get viewer counts
fetch('/api/live/viewers')
  .then(response => response.json())
  .then(data => {
    if (data.success) {
      console.log(`Total viewers: ${data.total_viewers}`);
      Object.entries(data.viewer_data).forEach(([channel, info]) => {
        console.log(`${channel}: ${info.viewers} viewers (${info.status})`);
      });
    }
  });
```

### Python
```python
import requests

# Login first
session = requests.Session()
login_response = session.post('http://localhost:5000/login', json={
    'username': 'user',
    'password': '1234567890'
})

# Get live status
response = session.get('http://localhost:5000/api/live/status')
data = response.json()

if data['success']:
    print(f"Live: {data['is_live']}")
    print(f"Total viewers: {data['total_viewers']}")
    for channel in data['live_channels']:
        print(f"Channel {channel['channel_id']}: {channel['viewers']} viewers")
```

## Error Handling

All endpoints return a consistent error format:
```json
{
  "success": false,
  "error": "Error message description"
}
```

Common HTTP status codes:
- `200`: Success
- `401`: Unauthorized (not logged in)
- `404`: Channel not found
- `500`: Internal server error

## Rate Limiting

- No rate limiting implemented
- YouTube API has its own rate limits
- Consider implementing caching for high-frequency requests

## Authentication

All API endpoints require authentication. Include session cookies or implement proper authentication headers.

## Real-time Updates

For real-time updates, consider:
1. Polling endpoints every 2-5 seconds
2. Implementing WebSocket connections
3. Using Server-Sent Events (SSE)
