# YouTube Live Dashboard - API Quick Reference

## 🔐 Authentication
**Public API:** No authentication required for live streaming endpoints!

**Public Pages:**
- Channel Authorization: `http://localhost:5005/authorize` - Anyone can add channels

**Admin Functions:** Login required for dashboard management
```bash
# Login (for admin functions only)
curl -X POST "http://localhost:5005/login" \
  -H "Content-Type: application/json" \
  -d '{"username": "user", "password": "1234567890"}'
```

## 📊 API Endpoints

### 1. Live Status
```bash
GET /api/live/status
```
**Returns:** Overall live status, total viewers, live channels list

### 2. Channel URLs
```bash
GET /api/live/channels
```
**Returns:** All live channel URLs and basic info

### 3. Viewer Counts
```bash
GET /api/live/viewers
```
**Returns:** Real-time viewer counts for all channels

### 4. Channel Details
```bash
GET /api/live/channel/<channel_id>
```
**Returns:** Detailed info for specific channel

## 🚀 Quick Examples

### JavaScript
```javascript
// Get live status - No authentication needed!
fetch('/api/live/status')
  .then(r => r.json())
  .then(data => console.log(data));

// Monitor viewers
setInterval(() => {
  fetch('/api/live/viewers')
    .then(r => r.json())
    .then(data => console.log(`Viewers: ${data.total_viewers}`));
}, 5000);
```

### Python
```python
import requests

# No login required for public API!
response = requests.get('http://localhost:5005/api/live/status')
print(response.json())

# Get viewers
viewers = requests.get('http://localhost:5005/api/live/viewers')
print(viewers.json())
```

### cURL
```bash
# Get live status - No authentication needed!
curl -X GET "http://localhost:5005/api/live/status"

# Get viewers
curl -X GET "http://localhost:5005/api/live/viewers"

# Get channel details
curl -X GET "http://localhost:5005/api/live/channel/UCImw27DBFWp6VLU9Joi4ZIA"
```

## 📈 Response Examples

### Live Status Response
```json
{
  "success": true,
  "is_live": true,
  "total_viewers": 150,
  "live_channels": [
    {
      "channel_id": "UCImw27DBFWp6VLU9Joi4ZIA",
      "title": "My Live Stream",
      "viewers": 75,
      "live_url": "https://www.youtube.com/watch?v=abc123"
    }
  ]
}
```

### Viewer Count Response
```json
{
  "success": true,
  "total_viewers": 150,
  "viewer_data": {
    "UCImw27DBFWp6VLU9Joi4ZIA": {
      "viewers": 75,
      "status": "live"
    }
  }
}
```

## ⚡ Testing
```bash
# Run test script
python test_api.py

# Start server
python app.py
```

## 🔧 Error Codes
- `200` - Success
- `401` - Not logged in
- `404` - Channel not found
- `500` - Server error

## 📝 Notes
- All endpoints require authentication
- Use session cookies for requests
- Poll every 5-10 seconds for real-time updates
- Check `API_DOCUMENTATION.md` for full details
