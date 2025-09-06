# YouTube Live Streaming Tool

A simple Python application that allows you to create and manage YouTube live streams using the YouTube Data API v3.

## Features

- OAuth 2.0 authentication with YouTube
- Create and schedule live events
- Get RTMP URL and stream key for streaming software
- Simple web interface

## Prerequisites

- Python 3.7+
- Google Cloud Project with YouTube Data API v3 enabled
- OAuth 2.0 credentials from Google Cloud Console

## Setup Instructions

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd youtube-live-tool
   ```

2. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Configure OAuth 2.0**
   - Go to [Google Cloud Console](https://console.cloud.google.com/)
   - Create a new project or select an existing one
   - Enable the YouTube Data API v3
   - Create OAuth 2.0 credentials (Web application)
   - Add `http://localhost:5000/oauth2callback` as an authorized redirect URI
   - Download the credentials JSON file

4. **Configure the application**
   - Copy your client ID and client secret to the `GOOGLE_CLIENT_CONFIG` in `app.py`
   - Set a secure `app.secret_key` in `app.py`

5. **Run the application**
   ```bash
   python app.py
   ```

6. **Access the application**
   Open your browser and go to `http://localhost:5000`

## Usage

1. Click "Authorize with YouTube" and sign in with your Google account
2. Click "Create Live Event" to create a new live stream
3. Use the provided RTMP URL and stream key in your streaming software (like OBS)

## Security Notes

- Never commit your client secret or refresh tokens to version control
- Use environment variables or a secure secret manager in production
- The current implementation is for development purposes only

## License

MIT
