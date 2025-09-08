import os
import json
import threading
import subprocess
from datetime import datetime, timedelta
from flask import Flask, redirect, url_for, session, request, render_template, Response, jsonify
from flask_cors import CORS
from flask_mail import Mail, Message
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request
from google.auth.exceptions import RefreshError
from functools import wraps

app = Flask(__name__)
app.secret_key = 'your-secure-secret-key-here'  # Change this to a secure secret key

# Enable CORS for all routes
CORS(app, origins=['*'], allow_headers=['Content-Type', 'Authorization'], methods=['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'])

# Email Configuration
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'iinsaftest@gmail.com'
app.config['MAIL_PASSWORD'] = 'clstvanemhrttcio'
app.config['MAIL_DEFAULT_SENDER'] = 'iinsaftest@gmail.com'

# Initialize Flask-Mail
mail = Mail(app)

# CORS response decorator for API endpoints
def cors_response(response):
    """Add CORS headers to response"""
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Methods'] = 'GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type', 'Authorization'
    return response

# Authentication credentials
VALID_CREDENTIALS = {
    'user': '1234567890'
}

# Authentication decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('logged_in'):
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# OAuth 2.0 Configuration
SCOPES = ['https://www.googleapis.com/auth/youtube.force-ssl']
API_SERVICE_NAME = 'youtube'
API_VERSION = 'v3'

# Save client config
os.makedirs('tokens', exist_ok=True)
# Get the absolute path to client_secrets.json in the parent directory
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
CLIENT_SECRETS_FILE = os.path.join(parent_dir, 'client_secrets.json')
TOKEN_FILE = 'tokens/token.json'

# For development only - allows HTTP for localhost
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

EVENTS_FILE = os.path.join(current_dir, 'events.json')
DRAFTS_FILE = os.path.join(current_dir, 'drafts.json')
HISTORY_FILE = os.path.join(current_dir, 'stream_history.json')

def save_event(event_data):
    # Thread-safe append to events.json
    lock = threading.Lock()
    with lock:
        if os.path.exists(EVENTS_FILE):
            with open(EVENTS_FILE, 'r') as f:
                try:
                    events = json.load(f)
                except Exception:
                    events = []
        else:
            events = []
        events.append(event_data)
        with open(EVENTS_FILE, 'w') as f:
            json.dump(events, f, indent=2)

# --- Multi-account credential helpers ---
def load_all_tokens():
    if os.path.exists(TOKEN_FILE):
        with open(TOKEN_FILE, 'r') as f:
            try:
                return json.load(f)
            except Exception:
                return {}
    return {}

def save_all_tokens(tokens):
    with open(TOKEN_FILE, 'w') as f:
        json.dump(tokens, f, indent=2)

# --- Draft management functions ---
def load_drafts():
    if os.path.exists(DRAFTS_FILE):
        with open(DRAFTS_FILE, 'r') as f:
            try:
                return json.load(f)
            except Exception:
                return {}
    return {}

def save_drafts(drafts):
    with open(DRAFTS_FILE, 'w') as f:
        json.dump(drafts, f, indent=2)

def save_draft(draft_id, draft_data):
    drafts = load_drafts()
    drafts[draft_id] = {
        **draft_data,
        'created_at': datetime.utcnow().isoformat(),
        'updated_at': datetime.utcnow().isoformat(),
        'is_shared': draft_data.get('is_shared', False),
        'share_token': draft_data.get('share_token', None)
    }
    save_drafts(drafts)
    return draft_id

def get_draft(draft_id):
    drafts = load_drafts()
    return drafts.get(draft_id)

def delete_draft(draft_id):
    drafts = load_drafts()
    if draft_id in drafts:
        del drafts[draft_id]
        save_drafts(drafts)
        return True
    return False

def get_draft_by_share_token(share_token):
    """Get draft by share token for shared access"""
    drafts = load_drafts()
    for draft_id, draft_data in drafts.items():
        if draft_data.get('share_token') == share_token:
            return draft_id, draft_data
    return None, None

def generate_share_token():
    """Generate a unique share token for draft sharing"""
    import secrets
    return secrets.token_urlsafe(16)

# --- Stream History Management Functions ---
def load_history():
    if os.path.exists(HISTORY_FILE):
        with open(HISTORY_FILE, 'r') as f:
            try:
                return json.load(f)
            except Exception:
                return []
    return []

def save_history(history):
    with open(HISTORY_FILE, 'w') as f:
        json.dump(history, f, indent=2)

def add_stream_session(session_data):
    history = load_history()
    session_id = f"session_{int(datetime.utcnow().timestamp())}"
    
    session_entry = {
        'session_id': session_id,
        'start_time': session_data.get('start_time'),
        'end_time': session_data.get('end_time'),
        'duration': session_data.get('duration'),
        'title': session_data.get('title', ''),
        'description': session_data.get('description', ''),
        'thumbnail_filename': session_data.get('thumbnail_filename'),
        'channels_used': session_data.get('channels_used', []),
        'live_urls': session_data.get('live_urls', {}),
        'viewer_stats': session_data.get('viewer_stats', {}),
        'status': session_data.get('status', 'completed'),  # completed, failed, interrupted
        'created_at': datetime.utcnow().isoformat()
    }
    
    history.insert(0, session_entry)  # Add to beginning for newest first
    save_history(history)
    return session_id

def update_stream_session(session_id, updates):
    history = load_history()
    for session in history:
        if session['session_id'] == session_id:
            session.update(updates)
            session['updated_at'] = datetime.utcnow().isoformat()
            save_history(history)
            return True
    return False

def get_stream_history(limit=None):
    history = load_history()
    if limit:
        return history[:limit]
    return history

def delete_stream_session(session_id):
    history = load_history()
    for i, session in enumerate(history):
        if session['session_id'] == session_id:
            # Delete thumbnail file if exists
            if session.get('thumbnail_filename'):
                thumbnail_path = os.path.join(current_dir, 'uploads', session['thumbnail_filename'])
                if os.path.exists(thumbnail_path):
                    os.remove(thumbnail_path)
            
            del history[i]
            save_history(history)
            return True
    return False

# Main function to get authenticated service for a given user/channel_id
def get_authenticated_service(user_id=None):
    tokens = load_all_tokens()
    if not user_id:
        user_id = session.get('current_channel_id')
    if not user_id or user_id not in tokens:
        return None  # No account available
    token_entry = tokens[user_id]
    # Support both legacy and new format
    if isinstance(token_entry, dict) and 'creds' in token_entry:
        creds_data = token_entry['creds']
    else:
        creds_data = token_entry
    creds = Credentials(
        token=creds_data['token'],
        refresh_token=creds_data.get('refresh_token'),
        token_uri=creds_data['token_uri'],
        client_id=creds_data['client_id'],
        client_secret=creds_data['client_secret'],
        scopes=creds_data['scopes']
    )
    # Refresh token if expired
    if creds.expired and creds.refresh_token:
        try:
            creds.refresh(Request())
            # Save refreshed token
            tokens[user_id] = credentials_to_dict(creds)
            save_all_tokens(tokens)
        except RefreshError:
            return None
    return build(API_SERVICE_NAME, API_VERSION, credentials=creds)

def credentials_to_dict(credentials):
    return {
        'token': credentials.token,
        'refresh_token': credentials.refresh_token,
        'token_uri': credentials.token_uri,
        'client_id': credentials.client_id,
        'client_secret': credentials.client_secret,
        'scopes': credentials.scopes,
        'expiry': credentials.expiry.isoformat() if credentials.expiry else None
    }

def get_user_info(youtube):
    # Get the user's channel info (which includes email if permission is granted)
    channels_response = youtube.channels().list(mine=True, part="snippet").execute()
    if channels_response['items']:
        snippet = channels_response['items'][0]['snippet']
        name = snippet.get('title', 'Unknown')
        # Email is not always available from YouTube API, so fallback to session if present
        email = session.get('user_email', 'Unknown')
        return name, email
    return 'Unknown', 'Unknown'

# Authentication routes
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        # If already logged in, redirect to dashboard
        if session.get('logged_in'):
            return redirect(url_for('index'))
        return render_template('login.html')
    
    elif request.method == 'POST':
        data = request.get_json()
        username = data.get('username', '').strip()
        password = data.get('password', '').strip()
        
        # Check credentials
        if username in VALID_CREDENTIALS and VALID_CREDENTIALS[username] == password:
            session['logged_in'] = True
            session['username'] = username
            return jsonify({'success': True, 'message': 'Login successful'})
        else:
            return jsonify({'success': False, 'message': 'Invalid username or password'}), 401

@app.route('/logout')
def logout():
    # Revoke the current user's token and reset their session
    if 'credentials' in session:
        try:
            creds = Credentials(**session['credentials'])
            revoke = Request()
            revoke.url = 'https://oauth2.googleapis.com/revoke'
            revoke.data = {'token': creds.token}
            revoke.headers['Content-type'] = 'application/x-www-form-urlencoded'
            revoke.method = 'POST'
            revoke.execute()
        except Exception as e:
            print(f"Error revoking token: {e}")
    
    # Clear session
    session.clear()
    
    # Delete token file if it exists
    if os.path.exists(TOKEN_FILE):
        os.remove(TOKEN_FILE)
    
    return redirect(url_for('login'))

@app.route('/')
@login_required
def index():
    tokens = load_all_tokens()
    current_channel_id = session.get('current_channel_id')
    accounts = []
    channel_list = []
    
    for cid, entry in tokens.items():
        name = entry.get('channel_name') if isinstance(entry, dict) else cid
        accounts.append({
            'id': cid,
            'name': name,
            'active': cid == current_channel_id
        })
        
        # Prepare detailed channel information for the channel list
        if isinstance(entry, dict) and 'creds' in entry:
            creds_data = entry['creds']
            expiry_date = None
            if 'expiry' in creds_data and creds_data['expiry']:
                try:
                    expiry_date = datetime.fromisoformat(creds_data['expiry'].replace('Z', '+00:00'))
                except:
                    expiry_date = None
            
            channel_list.append({
                'id': cid,
                'name': name,
                'expiry_date': expiry_date,
                'expiry_str': creds_data.get('expiry', 'Unknown'),
                'active': cid == current_channel_id
            })
    
    # Example: stream_info = {'rtmp_url': '...', 'stream_key': '...'}
    stream_info = None  # You can fill this with real data if needed
    credentials = bool(tokens)
    current_time = datetime.utcnow()
    return render_template('index.html', accounts=accounts, channel_list=channel_list, current_channel_id=current_channel_id, stream_info=stream_info, credentials=credentials, now=current_time)


@app.route('/switch_account/<channel_id>')
@login_required
def switch_account(channel_id):
    tokens = load_all_tokens()
    if channel_id in tokens:
        session['current_channel_id'] = channel_id
    return redirect(url_for('index'))

@app.route('/authorize')
def authorize():
    """Render the authorization form page"""
    return render_template('authorize.html')

@app.route('/reporters')
def reporters():
    """Render the reporters page"""
    return render_template('reporters.html')

@app.route('/save_user_info', methods=['POST'])
def save_user_info():
    """Save user information before authorization"""
    try:
        data = request.get_json()
        user_info = {
            'name': data.get('name', '').strip(),
            'email': data.get('email', '').strip(),
            'phone': data.get('phone', '').strip()
        }
        
        # Store in session
        session['user_info'] = user_info
        
        return jsonify({'success': True, 'message': 'User information saved successfully'})
    except Exception as e:
        return jsonify({'success': False, 'message': f'Error saving user information: {str(e)}'}), 500

@app.route('/authorize_oauth')
def authorize_oauth():
    """Handle the actual OAuth authorization"""
    try:
        # Check if client_secrets.json exists
        if not os.path.exists(CLIENT_SECRETS_FILE):
            return f'''
                <h2>Error: Client Secrets File Not Found</h2>
                <p>The file {CLIENT_SECRETS_FILE} was not found.</p>
                <p>Current working directory: {os.getcwd()}</p>
                <p>Looking for file at: {os.path.abspath(CLIENT_SECRETS_FILE)}</p>
                <p>Please ensure you have downloaded the client_secrets.json file from Google Cloud Console.</p>
                <p><a href="/">Back to Home</a></p>
            '''
        
        flow = Flow.from_client_secrets_file(
            CLIENT_SECRETS_FILE,
            scopes=SCOPES,
            redirect_uri=url_for('oauth2callback', _external=True)
        )
        
        # Ensure we get a refresh token
        authorization_url, state = flow.authorization_url(
            access_type='offline',
            include_granted_scopes='true',
            prompt='consent'  # This ensures we get a refresh token
        )
        
        session['state'] = state
        return redirect(authorization_url)
    except Exception as e:
        return f'''
            <h2>Error during authorization setup</h2>
            <p>Error: {str(e)}</p>
            <p>Please check your client_secrets.json file and ensure it's properly formatted.</p>
            <p><a href="/">Back to Home</a></p>
        '''

@app.route('/oauth2callback')
def oauth2callback():
    try:
        state = session['state']
        flow = Flow.from_client_secrets_file(
            CLIENT_SECRETS_FILE,
            scopes=SCOPES,
            state=state,
            redirect_uri=url_for('oauth2callback', _external=True)
        )
        # Fetch the OAuth 2.0 tokens
        flow.fetch_token(authorization_response=request.url)
        creds = flow.credentials
        youtube = build(API_SERVICE_NAME, API_VERSION, credentials=creds)
        channels_response = youtube.channels().list(mine=True, part="snippet").execute()
        if channels_response['items']:
            channel_id = channels_response['items'][0]['id']
            snippet = channels_response['items'][0]['snippet']
            
            # Get user info from session if available
            user_info = session.get('user_info', {})
            
            session['user_name'] = user_info.get('name', snippet.get('title', 'Unknown'))
            session['user_email'] = user_info.get('email', 'Unknown')
            session['user_phone'] = user_info.get('phone', 'Unknown')
            session['current_channel_id'] = channel_id
        else:
            channel_id = None
            user_info = session.get('user_info', {})
            session['user_name'] = user_info.get('name', 'Unknown')
            session['user_email'] = user_info.get('email', 'Unknown')
            session['user_phone'] = user_info.get('phone', 'Unknown')
            session['current_channel_id'] = None
        # Save credentials to token.json under channel_id
        if channel_id:
            tokens = load_all_tokens()
            tokens[channel_id] = {
                "creds": credentials_to_dict(creds),
                "channel_name": snippet.get("title", "Unknown"),
                "user_name": user_info.get('name', 'Unknown'),
                "user_email": user_info.get('email', 'Unknown'),
                "user_phone": user_info.get('phone', 'Unknown')
            }
            save_all_tokens(tokens)
        return redirect(url_for('index'))
    except Exception as e:
        return f'''
            <h2>Error during authorization</h2>
            <p>Error: {str(e)}</p>
            <p>This could be due to:</p>
            <ul>
                <li>Invalid client credentials in client_secrets.json</li>
                <li>YouTube Data API v3 not enabled in Google Cloud Console</li>
                <li>Incorrect redirect URI configuration</li>
            </ul>
            <p><a href="/">Back to Home</a></p>
        '''

@app.route('/create_live_event')
def create_live_event():
    try:
        youtube = get_authenticated_service()
        # If not authenticated, get_authenticated_service returns a redirect response
        if not hasattr(youtube, 'liveBroadcasts'):
            return youtube
        
        # Get user info
        user_name = session.get('user_name', 'Unknown')
        user_email = session.get('user_email', 'Unknown')
        # Schedule a live event for 5 minutes from now
        start_time = (datetime.utcnow() + timedelta(minutes=2)).isoformat() + 'Z'
        end_time = (datetime.utcnow() + timedelta(hours=1)).isoformat() + 'Z'
        
        # Create a liveBroadcast resource
        broadcast = youtube.liveBroadcasts().insert(
            part="snippet,status",
            body={
                "snippet": {
                    "title": f"{user_name}'s Live Stream",
                    "description": f"Live stream via YouTube API for {user_name}",
                    "scheduledStartTime": start_time,
                    "scheduledEndTime": end_time
                },
                "status": {
                    "privacyStatus": "public",
                    "selfDeclaredMadeForKids": False
                }
            }   
        ).execute()
        
        # Create a stream
        stream = youtube.liveStreams().insert(
            part="snippet,cdn",
            body={
                "snippet": {
                    "title": f"{user_name}'s Stream"
                },
                "cdn": {
                    "frameRate": "30fps",
                    "ingestionType": "rtmp",
                    "resolution": "720p"
                }
            }
        ).execute()
        
        # Bind the stream to the broadcast
        youtube.liveBroadcasts().bind(
            part="id,contentDetails",
            id=broadcast['id'],
            streamId=stream['id']
        ).execute()
        
        # Get stream details
        rtmp_url = stream['cdn']['ingestionInfo']['ingestionAddress']
        stream_key = stream['cdn']['ingestionInfo']['streamName']
        
        # Save event data
        event_data = {
            'user_name': user_name,
            'user_email': user_email,
            'rtmp_url': rtmp_url,
            'stream_key': stream_key,
            'created_at': datetime.utcnow().isoformat() + 'Z'
        }
        save_event(event_data)
        
        return f'''
            <h2>Live Event Created Successfully!</h2>
            <h3>User: {user_name}</h3>
            <h3>Email: {user_email}</h3>
            <h3>Stream URL: {rtmp_url}</h3>
            <h3>Stream Key: {stream_key}</h3>
            <p>Use these details in your streaming software (like OBS).</p>
            <p><a href="/">Back to Home</a></p>
        '''
    except Exception as e:
        return f'An error occurred: {str(e)}'


# Remove the old logout route as we have a new one above

import tempfile
from flask import send_from_directory

# Store ffmpeg process and pipe globally for simplicity (single user/session)
ffmpeg_process = None
ffmpeg_stdin = None
rtmp_url = None
stream_key = None
ffmpeg_output_buffer = []
ffmpeg_output_lock = threading.Lock()

def get_latest_stream_info():
    # Get the latest event (stream URL/key) from events.json
    if os.path.exists(EVENTS_FILE):
        with open(EVENTS_FILE, 'r') as f:
            try:
                events = json.load(f)
                if events:
                    return events[-1]['rtmp_url'], events[-1]['stream_key']
            except Exception:
                pass
    return None, None



@app.route('/upload_stream', methods=['POST'])
def upload_stream():
    global ffmpeg_process, ffmpeg_stdin, rtmp_url, stream_key
    chunk = request.files['chunk'].read()
    # Start ffmpeg process if not started
    if ffmpeg_process is None or ffmpeg_process.poll() is not None:
        # Use a pipe for stdin
        ffmpeg_cmd = [
            'ffmpeg',
            '-y',
            '-f', 'webm',
            '-i', 'pipe:0',
            '-c:v', 'libx264',
            '-preset', 'veryfast',
            '-pix_fmt', 'yuv420p',
            '-b:v', '3000k',
            '-c:a', 'aac',
            '-ar', '44100',
            '-b:a', '128k',
            '-f', 'flv',
            f'{rtmp_url}/{stream_key}'
        ]
        ffmpeg_process = subprocess.Popen(ffmpeg_cmd, stdin=subprocess.PIPE)
        ffmpeg_stdin = ffmpeg_process.stdin
    if ffmpeg_stdin:
        try:
            ffmpeg_stdin.write(chunk)
            ffmpeg_stdin.flush()
        except Exception as e:
            print(f'Error writing to ffmpeg: {e}')
    return ('', 204)

# --- INSTANT GO LIVE FEATURE START ---
from flask import send_file

@app.route('/instant_go_live')
@login_required
def instant_go_live():
    tokens = load_all_tokens()
    current_channel_id = session.get('current_channel_id')
    if not current_channel_id or current_channel_id not in tokens:
        return '''
            <h2>No account connected</h2>
            <p>Please <a href="/authorize">authorize with YouTube</a> first.</p>
            <p><a href="/">Back to Home</a></p>
        '''
    return render_template('instant_go_live.html')

@app.route('/instant_create_stream', methods=['POST'])
def instant_create_stream():
    try:
        youtube = get_authenticated_service()
        if not hasattr(youtube, 'liveStreams'):
            return jsonify({'error': 'Not authenticated'}), 401
        user_name = session.get('user_name', 'Instant User')
        # Create live stream only (not broadcast)
        stream = youtube.liveStreams().insert(
            part="snippet,cdn",
            body={
                "snippet": {"title": f"{user_name}'s Instant Stream"},
                "cdn": {
                    "frameRate": "30fps",
                    "ingestionType": "rtmp",
                    "resolution": "720p"
                }
            }
        ).execute()
        rtmp = stream['cdn']['ingestionInfo']['ingestionAddress']
        key = stream['cdn']['ingestionInfo']['streamName']
        session['instant_rtmp_url'] = rtmp
        session['instant_stream_key'] = key
        session['instant_stream_id'] = stream['id']
        return jsonify({'rtmp_url': rtmp, 'stream_key': key})
    except Exception as e:
        import traceback
        tb = traceback.format_exc()
        print(f"[instant_create_stream] Exception: {tb}")
        # Handle YouTube live streaming not enabled
        try:
            from googleapiclient.errors import HttpError
            if isinstance(e, HttpError):
                content = e.content.decode() if hasattr(e, 'content') and hasattr(e.content, 'decode') else str(e)
                if 'not enabled for live streaming' in content:
                    return jsonify({'error': "Live streaming is not enabled on your YouTube account. Please enable it at <a href='https://www.youtube.com/features' target='_blank'>YouTube Features</a> and try again."}), 403
        except ImportError:
            pass
        err_msg = str(e) or 'Unknown error (see server logs)'
        return jsonify({'error': err_msg}), 500

@app.route('/instant_go_live', methods=['POST'])
def instant_go_live_backend():
    try:
        youtube = get_authenticated_service()
        if not hasattr(youtube, 'liveBroadcasts'):
            return jsonify({'error': 'Not authenticated'}), 401
        user_name = session.get('user_name', 'Instant User')
        start_time = (datetime.utcnow()).isoformat() + 'Z'
        end_time = (datetime.utcnow() + timedelta(hours=2)).isoformat() + 'Z'
        stream_id = session.get('instant_stream_id')
        if not stream_id:
            return jsonify({'error': 'No stream created'}), 400
        # Create live broadcast
        broadcast = youtube.liveBroadcasts().insert(
            part="snippet,status,contentDetails",
            body={
                "snippet": {
                    "title": f"{user_name}'s Instant Live Stream",
                    "description": f"Instant live via YouTube API for {user_name}",
                    "scheduledStartTime": start_time,
                    "scheduledEndTime": end_time
                },
                "status": {
                    "privacyStatus": "public",
                    "selfDeclaredMadeForKids": False
                },
                "contentDetails": {
                    "enableAutoStart": True,
                    "enableAutoStop": True
                }
            }
        ).execute()
        # Bind
        youtube.liveBroadcasts().bind(
            part="id,contentDetails",
            id=broadcast['id'],
            streamId=stream_id
        ).execute()
        # Transition to live
        youtube.liveBroadcasts().transition(
            broadcastStatus="live",
            id=broadcast['id'],
            part="status"
        ).execute()
        live_url = f"https://www.youtube.com/watch?v={broadcast['id']}"
        session['instant_broadcast_id'] = broadcast['id']
        return jsonify({'live_url': live_url})
    except Exception as e:
        import traceback
        tb = traceback.format_exc()
        print(f"[instant_go_live] Exception: {tb}")
        err_msg = str(e) or 'Unknown error (see server logs)'
        return jsonify({'error': err_msg}), 500

@app.route('/instant_upload_stream', methods=['POST'])
def instant_upload_stream():
    global ffmpeg_process, ffmpeg_stdin
    chunk = request.files['chunk'].read()
    rtmp_url = session.get('instant_rtmp_url')
    stream_key = session.get('instant_stream_key')
    if not rtmp_url or not stream_key:
        return 'No RTMP info', 400
    if ffmpeg_process is None or ffmpeg_process.poll() is not None:
        ffmpeg_cmd = [
            'ffmpeg',
            '-y',
            '-f', 'webm',
            '-i', 'pipe:0',
            '-c:v', 'libx264',
            '-preset', 'veryfast',
            '-pix_fmt', 'yuv420p',
            '-b:v', '3000k',
            '-c:a', 'aac',
            '-ar', '44100',
            '-b:a', '128k',
            '-f', 'flv',
            f'{rtmp_url}/{stream_key}'
        ]
        ffmpeg_process = subprocess.Popen(ffmpeg_cmd, stdin=subprocess.PIPE)
        ffmpeg_stdin = ffmpeg_process.stdin
    try:
        ffmpeg_stdin.write(chunk)
        ffmpeg_stdin.flush()
    except Exception:
        pass
    return 'ok'

@app.route('/instant_ffmpeg_status')
def instant_ffmpeg_status():
    global ffmpeg_output_buffer
    # Return the last 10 lines of ffmpeg output (all types, not just stats)
    with ffmpeg_output_lock:
        output_lines = ffmpeg_output_buffer[-10:]
    return jsonify({'output': '\n'.join(output_lines) if output_lines else '(no ffmpeg output yet)'})

@app.route('/instant_stop_stream', methods=['POST'])
def instant_stop_stream():
    global ffmpeg_process, ffmpeg_stdin
    try:
        if ffmpeg_stdin:
            ffmpeg_stdin.close()
        if ffmpeg_process:
            ffmpeg_process.terminate()
    except Exception:
        pass
    ffmpeg_process = None
    ffmpeg_stdin = None
    return 'stopped'
# --- MULTI-CHANNEL INSTANT GO LIVE FEATURE START ---

from flask import send_file
multi_ffmpeg_processes = {}
multi_ffmpeg_stdin = {}
multi_rtmp_info = {}
multi_broadcast_ids = {}

@app.route('/multi_instant_go_live')
@login_required
def multi_instant_go_live():
    tokens = load_all_tokens()
    if not tokens:
        return '''<h2>No accounts connected</h2><p>Please <a href="/authorize">authorize with YouTube</a> first.</p><p><a href="/">Back to Home</a></p>'''
    return render_template('multi_instant_go_live.html')

@app.route('/multi_instant_channel_list')
def multi_instant_channel_list():
    tokens = load_all_tokens()
    channels = []
    for cid, entry in tokens.items():
        name = entry.get('channel_name') if isinstance(entry, dict) else cid
        channels.append({'channel_id': cid, 'channel_name': name})
    return jsonify({'channels': channels})

@app.route('/shared_draft_create_stream', methods=['POST'])
def shared_draft_create_stream():
    """Create stream from shared draft with thumbnail support"""
    tokens = load_all_tokens()
    live_urls = {}
    rtmp_info = {}
    broadcast_ids = {}
    errors = {}

    # Get meta fields from form data
    title = request.form.get('title') or 'Shared Draft Stream'
    description = request.form.get('description') or 'Live stream from shared draft'
    thumbnail_file = request.files.get('thumbnail')
    thumbnail_bytes = thumbnail_file.read() if thumbnail_file else None

    # Get selected channel IDs from frontend
    selected_channels = request.form.get('selected_channels')
    if selected_channels:
        try:
            selected_channels = set(json.loads(selected_channels))
        except Exception:
            selected_channels = set(tokens.keys())
    else:
        selected_channels = set(tokens.keys())

    for channel_id, creds_data in tokens.items():
        if channel_id not in selected_channels:
            continue
        try:
            youtube = get_authenticated_service(channel_id)
            user_name = channel_id
            start_time = (datetime.utcnow()).isoformat() + 'Z'
            end_time = (datetime.utcnow() + timedelta(hours=2)).isoformat() + 'Z'
            # Create stream
            stream = youtube.liveStreams().insert(
                part="snippet,cdn",
                body={
                    "snippet": {"title": title},
                    "cdn": {
                        "frameRate": "30fps",
                        "resolution": "720p",
                        "ingestionType": "rtmp"
                    }
                }
            ).execute()
            stream_id = stream['id']
            ingestion_info = stream['cdn']['ingestionInfo']
            rtmp_url = ingestion_info['ingestionAddress']
            stream_key = ingestion_info['streamName']
            # Create broadcast
            broadcast = youtube.liveBroadcasts().insert(
                part="snippet,status,contentDetails",
                body={
                    "snippet": {
                        "title": title,
                        "description": description,
                        "scheduledStartTime": start_time,
                        "scheduledEndTime": end_time
                    },
                    "status": {
                        "privacyStatus": "public",
                        "selfDeclaredMadeForKids": False
                    },
                    "contentDetails": {
                        "enableAutoStart": True,
                        "enableAutoStop": True
                    }
                }
            ).execute()
            broadcast_id = broadcast['id']
            # Bind
            youtube.liveBroadcasts().bind(
                part="id,contentDetails",
                id=broadcast_id,
                streamId=stream_id
            ).execute()
            # Set thumbnail if provided
            if thumbnail_bytes:
                import io
                from googleapiclient.http import MediaIoBaseUpload
                from googleapiclient.errors import HttpError
                
                # Check file size (2MB limit)
                if len(thumbnail_bytes) > 2 * 1024 * 1024:
                    errors[channel_id] = f"Thumbnail too large: {len(thumbnail_bytes)/1024/1024:.2f}MB (max 2MB)"
                    continue
                
                try:
                    mimetype = thumbnail_file.mimetype or 'image/jpeg'
                    media = MediaIoBaseUpload(io.BytesIO(thumbnail_bytes), mimetype=mimetype)
                    youtube.thumbnails().set(
                        videoId=broadcast_id,
                        media_body=media
                    ).execute()
                except HttpError as e:
                    error_content = e.content.decode() if hasattr(e, 'content') and isinstance(e.content, bytes) else str(e)
                    if 'Media larger than' in error_content:
                        errors[channel_id] = f"Thumbnail too large for YouTube (max 2MB). Current: {len(thumbnail_bytes)/1024/1024:.2f}MB"
                    else:
                        errors[channel_id] = f"Thumbnail upload failed: {error_content}"
                    continue
                except Exception as e:
                    errors[channel_id] = f"Thumbnail upload error: {str(e)}"
                    continue
            rtmp_info[channel_id] = {'rtmp_url': rtmp_url, 'stream_key': stream_key}
            broadcast_ids[channel_id] = broadcast_id
        except Exception as e:
            errors[channel_id] = str(e)
    global multi_rtmp_info, multi_broadcast_ids
    multi_rtmp_info = rtmp_info
    multi_broadcast_ids = broadcast_ids
    if errors:
        # Format errors as a readable string for the frontend
        error_str = '<br>'.join([f"<b>{cid}</b>: {msg}" for cid, msg in errors.items()])
        return jsonify({'error': error_str})
    return jsonify({})

@app.route('/multi_instant_create_stream', methods=['POST'])
def multi_instant_create_stream():
    tokens = load_all_tokens()
    live_urls = {}
    rtmp_info = {}
    broadcast_ids = {}
    errors = {}

    # Get meta fields from form data
    title = request.form.get('title') or 'Multi-Channel Instant Stream'
    description = request.form.get('description') or 'Go live instantly on all your connected YouTube channels!'
    thumbnail_file = request.files.get('thumbnail')
    thumbnail_bytes = thumbnail_file.read() if thumbnail_file else None

    # Get selected channel IDs from frontend
    selected_channels = request.form.get('selected_channels')
    if selected_channels:
        try:
            selected_channels = set(json.loads(selected_channels))
        except Exception:
            selected_channels = set(tokens.keys())
    else:
        selected_channels = set(tokens.keys())

    for channel_id, creds_data in tokens.items():
        if channel_id not in selected_channels:
            continue
        try:
            youtube = get_authenticated_service(channel_id)
            user_name = channel_id
            start_time = (datetime.utcnow()).isoformat() + 'Z'
            end_time = (datetime.utcnow() + timedelta(hours=2)).isoformat() + 'Z'
            # Create stream
            stream = youtube.liveStreams().insert(
                part="snippet,cdn",
                body={
                    "snippet": {"title": title},
                    "cdn": {
                        "frameRate": "30fps",
                        "resolution": "720p",
                        "ingestionType": "rtmp"
                    }
                }
            ).execute()
            stream_id = stream['id']
            ingestion_info = stream['cdn']['ingestionInfo']
            rtmp_url = ingestion_info['ingestionAddress']
            stream_key = ingestion_info['streamName']
            # Create broadcast
            broadcast = youtube.liveBroadcasts().insert(
                part="snippet,status,contentDetails",
                body={
                    "snippet": {
                        "title": title,
                        "description": description,
                        "scheduledStartTime": start_time,
                        "scheduledEndTime": end_time
                    },
                    "status": {
                        "privacyStatus": "public",
                        "selfDeclaredMadeForKids": False
                    },
                    "contentDetails": {
                        "enableAutoStart": True,
                        "enableAutoStop": True
                    }
                }
            ).execute()
            broadcast_id = broadcast['id']
            # Bind
            youtube.liveBroadcasts().bind(
                part="id,contentDetails",
                id=broadcast_id,
                streamId=stream_id
            ).execute()
            # Set thumbnail if provided
            if thumbnail_bytes:
                import io
                from googleapiclient.http import MediaIoBaseUpload
                from googleapiclient.errors import HttpError
                
                # Check file size (2MB limit)
                if len(thumbnail_bytes) > 2 * 1024 * 1024:
                    errors[channel_id] = f"Thumbnail too large: {len(thumbnail_bytes)/1024/1024:.2f}MB (max 2MB)"
                    continue
                
                try:
                    mimetype = thumbnail_file.mimetype or 'image/jpeg'
                    media = MediaIoBaseUpload(io.BytesIO(thumbnail_bytes), mimetype=mimetype)
                    youtube.thumbnails().set(
                        videoId=broadcast_id,
                        media_body=media
                    ).execute()
                except HttpError as e:
                    error_content = e.content.decode() if hasattr(e, 'content') and isinstance(e.content, bytes) else str(e)
                    if 'Media larger than' in error_content:
                        errors[channel_id] = f"Thumbnail too large for YouTube (max 2MB). Current: {len(thumbnail_bytes)/1024/1024:.2f}MB"
                    else:
                        errors[channel_id] = f"Thumbnail upload failed: {error_content}"
                    continue
                except Exception as e:
                    errors[channel_id] = f"Thumbnail upload error: {str(e)}"
                    continue
            rtmp_info[channel_id] = {'rtmp_url': rtmp_url, 'stream_key': stream_key}
            broadcast_ids[channel_id] = broadcast_id
        except Exception as e:
            errors[channel_id] = str(e)
    global multi_rtmp_info, multi_broadcast_ids
    multi_rtmp_info = rtmp_info
    multi_broadcast_ids = broadcast_ids
    if errors:
        # Format errors as a readable string for the frontend
        error_str = '<br>'.join([f"<b>{cid}</b>: {msg}" for cid, msg in errors.items()])
        return jsonify({'error': error_str})
    return jsonify({})

@app.route('/multi_instant_go_live', methods=['POST'])
def multi_instant_go_live_backend():
    import time
    from googleapiclient.errors import HttpError
    tokens = load_all_tokens()
    results = {}
    for channel_id, creds_data in tokens.items():
        youtube = get_authenticated_service(channel_id)
        broadcast_id = multi_broadcast_ids.get(channel_id)
        if not broadcast_id:
            results[channel_id] = {'status': 'error', 'error': 'No broadcast created'}
            continue
        # Retry up to 10s if transition fails with 'Invalid transition'
        success = False
        error_msg = None
        for attempt in range(10):
            try:
                youtube.liveBroadcasts().transition(
                    broadcastStatus="live",
                    id=broadcast_id,
                    part="status"
                ).execute()
                live_url = f"https://www.youtube.com/watch?v={broadcast_id}"
                results[channel_id] = {'status': 'live', 'live_url': live_url}
                success = True
                break
            except HttpError as e:
                err_content = e.content.decode() if hasattr(e, 'content') and isinstance(e.content, bytes) else str(e)
                # Handle redundantTransition as success
                if 'reason' in err_content and 'redundantTransition' in err_content:
                    live_url = f"https://www.youtube.com/watch?v={broadcast_id}"
                    results[channel_id] = {'status': 'live', 'live_url': live_url}
                    success = True
                    break
                if 'Invalid transition' in err_content:
                    time.sleep(1)  # Wait and retry
                    continue
                else:
                    error_msg = err_content
                    break
            except Exception as e:
                error_msg = str(e)
                break
        if not success:
            if not error_msg:
                error_msg = 'Timeout: YouTube did not accept the transition to live.'
            results[channel_id] = {'status': 'error', 'error': error_msg}
    # Prepare frontend response
    live_urls = {cid: r['live_url'] for cid, r in results.items() if r['status'] == 'live'}
    errors = {cid: r['error'] for cid, r in results.items() if r['status'] == 'error'}
    resp = {'live_urls': live_urls}
    if errors:
        resp['errors'] = errors
    return jsonify(resp)

@app.route('/multi_instant_upload_stream', methods=['POST'])
def multi_instant_upload_stream():
    chunk = request.files['chunk'].read()
    global multi_ffmpeg_processes, multi_ffmpeg_stdin, multi_rtmp_info
    for channel_id, info in multi_rtmp_info.items():
        rtmp_url = info['rtmp_url']
        stream_key = info['stream_key']
        if channel_id not in multi_ffmpeg_processes or multi_ffmpeg_processes[channel_id] is None or multi_ffmpeg_processes[channel_id].poll() is not None:
            ffmpeg_cmd = [
                'ffmpeg',
                '-y',
                '-f', 'webm',
                '-i', 'pipe:0',
                '-c:v', 'libx264',
                '-preset', 'veryfast',
                '-pix_fmt', 'yuv420p',
                '-b:v', '3000k',
                '-c:a', 'aac',
                '-ar', '44100',
                '-b:a', '128k',
                '-f', 'flv',
                f'{rtmp_url}/{stream_key}'
            ]
            proc = subprocess.Popen(ffmpeg_cmd, stdin=subprocess.PIPE)
            multi_ffmpeg_processes[channel_id] = proc
            multi_ffmpeg_stdin[channel_id] = proc.stdin
        try:
            multi_ffmpeg_stdin[channel_id].write(chunk)
            multi_ffmpeg_stdin[channel_id].flush()
        except Exception:
            pass
    return 'ok'

@app.route('/multi_instant_stop_stream', methods=['POST'])
def multi_instant_stop_stream():
    global multi_ffmpeg_processes, multi_ffmpeg_stdin
    for cid in list(multi_ffmpeg_stdin.keys()):
        try:
            if multi_ffmpeg_stdin[cid]:
                multi_ffmpeg_stdin[cid].close()
        except Exception:
            pass
        multi_ffmpeg_stdin[cid] = None
    for cid in list(multi_ffmpeg_processes.keys()):
        try:
            if multi_ffmpeg_processes[cid]:
                multi_ffmpeg_processes[cid].terminate()
        except Exception:
            pass
        multi_ffmpeg_processes[cid] = None
    return 'stopped'

# --- MULTI-CHANNEL INSTANT GO LIVE FEATURE END ---

# --- EMAIL FUNCTIONS ---

def send_email(to_email, subject, body, html_body=None):
    """Send email to specified address"""
    try:
        msg = Message(
            subject=subject,
            recipients=[to_email],
            body=body,
            html=html_body
        )
        mail.send(msg)
        return True, "Email sent successfully"
    except Exception as e:
        return False, f"Failed to send email: {str(e)}"

def send_bulk_email(recipients, subject, body, html_body=None):
    """Send email to multiple recipients"""
    try:
        msg = Message(
            subject=subject,
            recipients=recipients,
            body=body,
            html=html_body
        )
        mail.send(msg)
        return True, f"Email sent successfully to {len(recipients)} recipients"
    except Exception as e:
        return False, f"Failed to send bulk email: {str(e)}"

# --- EMAIL API ENDPOINTS ---

@app.route('/api/email/send', methods=['POST'])
def send_single_email():
    """Send email to a single recipient"""
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'success': False, 'error': 'No data provided'}), 400
        
        required_fields = ['to', 'subject', 'body']
        for field in required_fields:
            if field not in data:
                return jsonify({'success': False, 'error': f'Missing required field: {field}'}), 400
        
        success, message = send_email(
            to_email=data['to'],
            subject=data['subject'],
            body=data['body'],
            html_body=data.get('html_body')
        )
        
        response = jsonify({
            'success': success,
            'message': message
        })
        return cors_response(response)
        
    except Exception as e:
        response = jsonify({'success': False, 'error': str(e)})
        return cors_response(response), 500

@app.route('/api/email/send-bulk', methods=['POST'])
def send_bulk_email_endpoint():
    """Send email to multiple recipients"""
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'success': False, 'error': 'No data provided'}), 400
        
        required_fields = ['recipients', 'subject', 'body']
        for field in required_fields:
            if field not in data:
                return jsonify({'success': False, 'error': f'Missing required field: {field}'}), 400
        
        if not isinstance(data['recipients'], list) or len(data['recipients']) == 0:
            return jsonify({'success': False, 'error': 'Recipients must be a non-empty list'}), 400
        
        success, message = send_bulk_email(
            recipients=data['recipients'],
            subject=data['subject'],
            body=data['body'],
            html_body=data.get('html_body')
        )
        
        response = jsonify({
            'success': success,
            'message': message
        })
        return cors_response(response)
        
    except Exception as e:
        response = jsonify({'success': False, 'error': str(e)})
        return cors_response(response), 500

@app.route('/api/email/send-to-reporters', methods=['POST'])
def send_email_to_reporters():
    """Send email to all reporters"""
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'success': False, 'error': 'No data provided'}), 400
        
        required_fields = ['subject', 'body']
        for field in required_fields:
            if field not in data:
                return jsonify({'success': False, 'error': f'Missing required field: {field}'}), 400
        
        # Get all reporters
        try:
            import requests
            api_url = "http://localhost:5000/user/reporter"
            external_response = requests.get(api_url, timeout=5)
            
            if external_response.status_code == 200:
                external_data = external_response.json()
                if 'data' in external_data and 'reporters' in external_data['data']:
                    reporters = external_data['data']['reporters']
                elif 'reporters' in external_data:
                    reporters = external_data['reporters']
                else:
                    return jsonify({'success': False, 'error': 'No reporters found'}), 404
            else:
                return jsonify({'success': False, 'error': 'Failed to fetch reporters'}), 500
                
        except requests.exceptions.RequestException:
            return jsonify({'success': False, 'error': 'External API not available'}), 500
        
        # Extract email addresses
        recipients = [reporter['email'] for reporter in reporters if reporter.get('email')]
        
        if not recipients:
            return jsonify({'success': False, 'error': 'No valid email addresses found'}), 400
        
        success, message = send_bulk_email(
            recipients=recipients,
            subject=data['subject'],
            body=data['body'],
            html_body=data.get('html_body')
        )
        
        response = jsonify({
            'success': success,
            'message': message,
            'recipients_count': len(recipients)
        })
        return cors_response(response)
        
    except Exception as e:
        response = jsonify({'success': False, 'error': str(e)})
        return cors_response(response), 500

# --- REPORTERS API ENDPOINTS ---

@app.route('/user/reporter')
def get_reporters():
    """Get all reporters from the system"""
    try:
        # Try to fetch from external API first
        import requests
        
        # Make request to the actual API
        api_url = "http://localhost:5000/user/reporter"
        
        try:
            # Try to get data from the external API
            external_response = requests.get(api_url, timeout=5)
            if external_response.status_code == 200:
                external_data = external_response.json()
                print(f"External API response: {external_data}")
                
                # Handle different response structures
                if 'data' in external_data and 'reporters' in external_data['data']:
                    # If data is nested under 'data' key
                    reporters = external_data['data']['reporters']
                    response = jsonify({
                        'success': True,
                        'reporters': reporters,
                        'count': len(reporters)
                    })
                    return cors_response(response)
                elif 'reporters' in external_data:
                    # If reporters is directly in response
                    reporters = external_data['reporters']
                    response = jsonify({
                        'success': True,
                        'reporters': reporters,
                        'count': len(reporters)
                    })
                    return cors_response(response)
                elif external_data.get('success'):
                    # If success is true but different structure
                    response = jsonify(external_data)
                    return cors_response(response)
        except requests.exceptions.RequestException as e:
            print(f"External API not available: {e}")
        
        # Fallback: Return empty list if external API is not available
        response = jsonify({
            'success': True,
            'reporters': [],
            'count': 0,
            'message': 'No external API available - using fallback'
        })
        return cors_response(response)
        
    except Exception as e:
        response = jsonify({'success': False, 'error': str(e)})
        return cors_response(response), 500

# --- LIVE STREAMING API ENDPOINTS ---

@app.route('/api/live/status')
def get_live_status():
    """Get overall live streaming status"""
    try:
        tokens = load_all_tokens()
        live_channels = []
        total_viewers = 0
        
        for channel_id in tokens.keys():
            broadcast_id = multi_broadcast_ids.get(channel_id)
            if broadcast_id:
                try:
                    youtube = get_authenticated_service(channel_id)
                    resp = youtube.liveBroadcasts().list(
                        part="snippet,status,statistics",
                        id=broadcast_id
                    ).execute()
                    
                    items = resp.get('items', [])
                    if items:
                        item = items[0]
                        status = item.get('status', {})
                        snippet = item.get('snippet', {})
                        statistics = item.get('statistics', {})
                        
                        if status.get('lifeCycleStatus') == 'live':
                            viewers = int(statistics.get('concurrentViewers', 0))
                            total_viewers += viewers
                            
                            live_channels.append({
                                'channel_id': channel_id,
                                'broadcast_id': broadcast_id,
                                'title': snippet.get('title', ''),
                                'viewers': viewers,
                                'live_url': f"https://www.youtube.com/watch?v={broadcast_id}",
                                'status': 'live'
                            })
                except Exception as e:
                    print(f"Error getting status for channel {channel_id}: {e}")
        
        response = jsonify({
            'success': True,
            'is_live': len(live_channels) > 0,
            'total_viewers': total_viewers,
            'live_channels': live_channels,
            'total_channels': len(live_channels)
        })
        return cors_response(response)
        
    except Exception as e:
        response = jsonify({'success': False, 'error': str(e)})
        return cors_response(response), 500

@app.route('/api/live/channels')
def get_live_channels():
    """Get all live channel URLs and basic info"""
    try:
        tokens = load_all_tokens()
        live_channels = []
        
        for channel_id in tokens.keys():
            broadcast_id = multi_broadcast_ids.get(channel_id)
            if broadcast_id:
                try:
                    youtube = get_authenticated_service(channel_id)
                    resp = youtube.liveBroadcasts().list(
                        part="snippet,status",
                        id=broadcast_id
                    ).execute()
                    
                    items = resp.get('items', [])
                    if items:
                        item = items[0]
                        status = item.get('status', {})
                        snippet = item.get('snippet', {})
                        
                        if status.get('lifeCycleStatus') == 'live':
                            live_channels.append({
                                'channel_id': channel_id,
                                'broadcast_id': broadcast_id,
                                'title': snippet.get('title', ''),
                                'live_url': f"https://www.youtube.com/watch?v={broadcast_id}",
                                'status': 'live'
                            })
                except Exception as e:
                    print(f"Error getting channel info for {channel_id}: {e}")
        
        response = jsonify({
            'success': True,
            'live_channels': live_channels,
            'count': len(live_channels)
        })
        return cors_response(response)
        
    except Exception as e:
        response = jsonify({'success': False, 'error': str(e)})
        return cors_response(response), 500

@app.route('/api/live/viewers')
def get_live_viewers():
    """Get viewer counts for all live channels"""
    try:
        tokens = load_all_tokens()
        viewer_data = {}
        total_viewers = 0
        
        for channel_id in tokens.keys():
            broadcast_id = multi_broadcast_ids.get(channel_id)
            if broadcast_id:
                try:
                    youtube = get_authenticated_service(channel_id)
                    resp = youtube.liveBroadcasts().list(
                        part="status,statistics",
                        id=broadcast_id
                    ).execute()
                    
                    items = resp.get('items', [])
                    if items:
                        item = items[0]
                        status = item.get('status', {})
                        statistics = item.get('statistics', {})
                        
                        if status.get('lifeCycleStatus') == 'live':
                            viewers = int(statistics.get('concurrentViewers', 0))
                            total_viewers += viewers
                            viewer_data[channel_id] = {
                                'viewers': viewers,
                                'status': 'live'
                            }
                        else:
                            viewer_data[channel_id] = {
                                'viewers': 0,
                                'status': 'offline'
                            }
                except Exception as e:
                    print(f"Error getting viewers for channel {channel_id}: {e}")
                    viewer_data[channel_id] = {
                        'viewers': None,
                        'status': 'error'
                    }
        
        response = jsonify({
            'success': True,
            'viewer_data': viewer_data,
            'total_viewers': total_viewers,
            'live_channels': len([v for v in viewer_data.values() if v['status'] == 'live'])
        })
        return cors_response(response)
        
    except Exception as e:
        response = jsonify({'success': False, 'error': str(e)})
        return cors_response(response), 500

@app.route('/api/live/channel/<channel_id>')
def get_channel_details(channel_id):
    """Get detailed info for a specific channel"""
    try:
        tokens = load_all_tokens()
        if channel_id not in tokens:
            response = jsonify({'success': False, 'error': 'Channel not found'})
            return cors_response(response), 404
        
        broadcast_id = multi_broadcast_ids.get(channel_id)
        if not broadcast_id:
            response = jsonify({'success': False, 'error': 'No active broadcast for this channel'})
            return cors_response(response), 404
        
        youtube = get_authenticated_service(channel_id)
        resp = youtube.liveBroadcasts().list(
            part="snippet,status,statistics,contentDetails",
            id=broadcast_id
        ).execute()
        
        items = resp.get('items', [])
        if not items:
            response = jsonify({'success': False, 'error': 'Broadcast not found'})
            return cors_response(response), 404
        
        item = items[0]
        snippet = item.get('snippet', {})
        status = item.get('status', {})
        statistics = item.get('statistics', {})
        content_details = item.get('contentDetails', {})
        
        response = jsonify({
            'success': True,
            'channel_id': channel_id,
            'broadcast_id': broadcast_id,
            'title': snippet.get('title', ''),
            'description': snippet.get('description', ''),
            'status': status.get('lifeCycleStatus', 'unknown'),
            'privacy_status': status.get('privacyStatus', 'unknown'),
            'viewers': int(statistics.get('concurrentViewers', 0)),
            'live_url': f"https://www.youtube.com/watch?v={broadcast_id}",
            'scheduled_start': snippet.get('scheduledStartTime'),
            'actual_start': snippet.get('actualStartTime'),
            'scheduled_end': snippet.get('scheduledEndTime'),
            'actual_end': snippet.get('actualEndTime'),
            'is_live': status.get('lifeCycleStatus') == 'live'
        })
        return cors_response(response)
        
    except Exception as e:
        response = jsonify({'success': False, 'error': str(e)})
        return cors_response(response), 500

@app.route('/multi_instant_viewers')
def multi_instant_viewers():
    """Legacy endpoint for backward compatibility"""
    from googleapiclient.errors import HttpError
    import concurrent.futures
    import threading
    
    tokens = load_all_tokens()
    results = {}
    
    def get_viewer_count(channel_id):
        try:
            youtube = get_authenticated_service(channel_id)
            broadcast_id = multi_broadcast_ids.get(channel_id)
            if not broadcast_id:
                return channel_id, None
            
            resp = youtube.liveBroadcasts().list(
                part="status,statistics",
                id=broadcast_id
            ).execute()
            
            items = resp.get('items', [])
            if items and 'statistics' in items[0]:
                viewers = items[0]['statistics'].get('concurrentViewers')
                return channel_id, int(viewers) if viewers is not None else 0
            else:
                return channel_id, 0
        except HttpError as e:
            print(f"HTTP Error for channel {channel_id}: {e}")
            return channel_id, None
        except Exception as e:
            print(f"Error getting viewers for channel {channel_id}: {e}")
            return channel_id, None
    
    # Use ThreadPoolExecutor for parallel API calls
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        future_to_channel = {
            executor.submit(get_viewer_count, channel_id): channel_id 
            for channel_id in tokens.keys()
        }
        
        for future in concurrent.futures.as_completed(future_to_channel):
            channel_id, viewer_count = future.result()
            results[channel_id] = viewer_count
    
    response = jsonify(results)
    return cors_response(response)

@app.route('/delete_channel/<channel_id>', methods=['POST'])
def delete_channel(channel_id):
    try:
        tokens = load_all_tokens()
        if channel_id in tokens:
            del tokens[channel_id]
            save_all_tokens(tokens)
            
            # If this was the current channel, clear the session
            if session.get('current_channel_id') == channel_id:
                session.pop('current_channel_id', None)
                session.pop('user_name', None)
                session.pop('user_email', None)
            
            return jsonify({'success': True, 'message': 'Channel deleted successfully'})
        else:
            return jsonify({'success': False, 'message': 'Channel not found'}), 404
    except Exception as e:
        return jsonify({'success': False, 'message': f'Error deleting channel: {str(e)}'}), 500

# --- Draft Management Routes ---
@app.route('/save_draft', methods=['POST'])
def save_draft_route():
    try:
        # Check if request contains files (FormData) or JSON
        if request.files:
            # Handle FormData request (with file upload)
            title = request.form.get('title', '').strip()
            description = request.form.get('description', '').strip()
            selected_channels_str = request.form.get('selected_channels', '[]')
            is_shared = request.form.get('is_shared', 'false').lower() == 'true'
            
            # Parse selected_channels JSON string
            try:
                selected_channels = json.loads(selected_channels_str)
            except json.JSONDecodeError:
                selected_channels = []
        else:
            # Handle JSON request
            data = request.get_json()
            title = data.get('title', '').strip()
            description = data.get('description', '').strip()
            selected_channels = data.get('selected_channels', [])
            is_shared = data.get('is_shared', False)
        
        if not title:
            return jsonify({'success': False, 'message': 'Title is required'}), 400
        
        # Generate a unique draft ID
        draft_id = f"draft_{int(datetime.utcnow().timestamp())}"
        
        draft_data = {
            'title': title,
            'description': description,
            'selected_channels': selected_channels,
            'thumbnail_filename': None,
            'is_shared': is_shared,
            'share_token': generate_share_token() if is_shared else None
        }
        
        # Handle thumbnail upload if present
        if 'thumbnail' in request.files:
            thumbnail_file = request.files['thumbnail']
            if thumbnail_file and thumbnail_file.filename:
                # Save thumbnail file
                filename = f"thumb_{int(datetime.utcnow().timestamp())}.jpg"
                upload_path = os.path.join(current_dir, 'uploads')
                os.makedirs(upload_path, exist_ok=True)
                thumbnail_path = os.path.join(upload_path, filename)
                thumbnail_file.save(thumbnail_path)
                draft_data['thumbnail_filename'] = filename
        
        save_draft(draft_id, draft_data)
        
        response_data = {
            'success': True, 
            'message': 'Draft saved successfully',
            'draft_id': draft_id
        }
        
        # Include share link if draft is shared
        if is_shared:
            response_data['share_link'] = f"/shared_draft/{draft_data['share_token']}"
        
        return jsonify(response_data)
        
    except Exception as e:
        return jsonify({'success': False, 'message': f'Error saving draft: {str(e)}'}), 500

@app.route('/get_drafts', methods=['GET'])
def get_drafts_route():
    try:
        drafts = load_drafts()
        # Convert to list format for frontend
        drafts_list = []
        for draft_id, draft_data in drafts.items():
            drafts_list.append({
                'id': draft_id,
                'title': draft_data.get('title', ''),
                'description': draft_data.get('description', ''),
                'created_at': draft_data.get('created_at', ''),
                'updated_at': draft_data.get('updated_at', ''),
                'thumbnail_filename': draft_data.get('thumbnail_filename'),
                'is_shared': draft_data.get('is_shared', False),
                'share_token': draft_data.get('share_token'),
                'selected_channels': draft_data.get('selected_channels', [])
            })
        
        # Sort by updated_at descending
        drafts_list.sort(key=lambda x: x.get('updated_at', ''), reverse=True)
        
        return jsonify({'success': True, 'drafts': drafts_list})
        
    except Exception as e:
        return jsonify({'success': False, 'message': f'Error loading drafts: {str(e)}'}), 500

@app.route('/get_draft/<draft_id>', methods=['GET'])
def get_draft_route(draft_id):
    try:
        draft = get_draft(draft_id)
        if not draft:
            return jsonify({'success': False, 'message': 'Draft not found'}), 404
        
        return jsonify({
            'success': True, 
            'draft': {
                'title': draft.get('title', ''),
                'description': draft.get('description', ''),
                'selected_channels': draft.get('selected_channels', []),
                'thumbnail_filename': draft.get('thumbnail_filename'),
                'is_shared': draft.get('is_shared', False),
                'share_token': draft.get('share_token')
            }
        })
        
    except Exception as e:
        return jsonify({'success': False, 'message': f'Error loading draft: {str(e)}'}), 500

@app.route('/update_draft/<draft_id>', methods=['POST'])
def update_draft_route(draft_id):
    try:
        # Check if request contains files (FormData) or JSON
        if request.files:
            # Handle FormData request (with file upload)
            title = request.form.get('title', '').strip()
            description = request.form.get('description', '').strip()
            selected_channels_str = request.form.get('selected_channels', '[]')
            is_shared = request.form.get('is_shared', 'false').lower() == 'true'
            
            # Parse selected_channels JSON string
            try:
                selected_channels = json.loads(selected_channels_str)
            except json.JSONDecodeError:
                selected_channels = []
        else:
            # Handle JSON request
            data = request.get_json()
            title = data.get('title', '').strip()
            description = data.get('description', '').strip()
            selected_channels = data.get('selected_channels', [])
            is_shared = data.get('is_shared', False)
        
        if not title:
            return jsonify({'success': False, 'message': 'Title is required'}), 400
        
        # Get existing draft
        existing_draft = get_draft(draft_id)
        if not existing_draft:
            return jsonify({'success': False, 'message': 'Draft not found'}), 404
        
        # Prepare updated draft data
        draft_data = {
            'title': title,
            'description': description,
            'selected_channels': selected_channels,
            'thumbnail_filename': existing_draft.get('thumbnail_filename'),  # Keep existing thumbnail
            'is_shared': is_shared,
            'share_token': existing_draft.get('share_token') if is_shared else None
        }
        
        # Generate new share token if becoming shared
        if is_shared and not existing_draft.get('share_token'):
            draft_data['share_token'] = generate_share_token()
        
        # Handle thumbnail upload if present
        if 'thumbnail' in request.files:
            thumbnail_file = request.files['thumbnail']
            if thumbnail_file and thumbnail_file.filename:
                # Delete old thumbnail if exists
                if existing_draft.get('thumbnail_filename'):
                    old_thumbnail_path = os.path.join(current_dir, 'uploads', existing_draft['thumbnail_filename'])
                    if os.path.exists(old_thumbnail_path):
                        os.remove(old_thumbnail_path)
                
                # Save new thumbnail file
                filename = f"thumb_{int(datetime.utcnow().timestamp())}.jpg"
                upload_path = os.path.join(current_dir, 'uploads')
                os.makedirs(upload_path, exist_ok=True)
                thumbnail_path = os.path.join(upload_path, filename)
                thumbnail_file.save(thumbnail_path)
                draft_data['thumbnail_filename'] = filename
        
        save_draft(draft_id, draft_data)
        
        response_data = {
            'success': True, 
            'message': 'Draft updated successfully',
            'draft_id': draft_id
        }
        
        # Include share link if draft is shared
        if is_shared:
            response_data['share_link'] = f"/shared_draft/{draft_data['share_token']}"
        
        return jsonify(response_data)
        
    except Exception as e:
        return jsonify({'success': False, 'message': f'Error updating draft: {str(e)}'}), 500

@app.route('/delete_draft/<draft_id>', methods=['POST'])
def delete_draft_route(draft_id):
    try:
        # Get draft to find thumbnail file
        draft = get_draft(draft_id)
        if draft and draft.get('thumbnail_filename'):
            # Delete thumbnail file
            thumbnail_path = os.path.join(current_dir, 'uploads', draft['thumbnail_filename'])
            if os.path.exists(thumbnail_path):
                os.remove(thumbnail_path)
        
        success = delete_draft(draft_id)
        if success:
            return jsonify({'success': True, 'message': 'Draft deleted successfully'})
        else:
            return jsonify({'success': False, 'message': 'Draft not found'}), 404
            
    except Exception as e:
        return jsonify({'success': False, 'message': f'Error deleting draft: {str(e)}'}), 500

@app.route('/load_draft/<draft_id>', methods=['POST'])
def load_draft_route(draft_id):
    try:
        draft = get_draft(draft_id)
        if not draft:
            return jsonify({'success': False, 'message': 'Draft not found'}), 404
        
        # Return draft data for the wizard
        return jsonify({
            'success': True,
            'draft': {
                'title': draft.get('title', ''),
                'description': draft.get('description', ''),
                'selected_channels': draft.get('selected_channels', []),
                'thumbnail_filename': draft.get('thumbnail_filename')
            }
        })
        
    except Exception as e:
        return jsonify({'success': False, 'message': f'Error loading draft: {str(e)}'}), 500

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    """Serve uploaded thumbnail files"""
    upload_path = os.path.join(current_dir, 'uploads')
    return send_from_directory(upload_path, filename)

# --- Shared Draft Routes ---
@app.route('/shared_draft/<share_token>')
def shared_draft_page(share_token):
    """Render the shared draft page for users to go live"""
    draft_id, draft_data = get_draft_by_share_token(share_token)
    if not draft_data:
        return '''
            <h2>Draft Not Found</h2>
            <p>The shared draft you're looking for doesn't exist or has been removed.</p>
            <p><a href="/">Back to Home</a></p>
        '''
    
    return render_template('shared_draft.html', draft=draft_data, share_token=share_token)

@app.route('/api/shared_draft/<share_token>')
def get_shared_draft_api(share_token):
    """API endpoint to get shared draft data"""
    draft_id, draft_data = get_draft_by_share_token(share_token)
    if not draft_data:
        return jsonify({'success': False, 'message': 'Draft not found'}), 404
    
    return jsonify({
        'success': True,
        'draft': {
            'title': draft_data.get('title', ''),
            'description': draft_data.get('description', ''),
            'selected_channels': draft_data.get('selected_channels', []),
            'thumbnail_filename': draft_data.get('thumbnail_filename'),
            'is_shared': draft_data.get('is_shared', False)
        }
    })

@app.route('/create_shared_draft')
@login_required
def create_shared_draft_page():
    """Render the admin page for creating shared drafts"""
    tokens = load_all_tokens()
    if not tokens:
        return '''<h2>No accounts connected</h2><p>Please <a href="/authorize">authorize with YouTube</a> first.</p><p><a href="/">Back to Home</a></p>'''
    return render_template('create_shared_draft.html')

@app.route('/save_thumbnail', methods=['POST'])
def save_thumbnail_route():
    """Save thumbnail file for history sessions"""
    try:
        if 'thumbnail' not in request.files:
            return jsonify({'success': False, 'message': 'No thumbnail file provided'}), 400
        
        thumbnail_file = request.files['thumbnail']
        filename = request.form.get('filename')
        
        if not filename:
            filename = f"thumb_{int(datetime.utcnow().timestamp())}.jpg"
        
        upload_path = os.path.join(current_dir, 'uploads')
        os.makedirs(upload_path, exist_ok=True)
        thumbnail_path = os.path.join(upload_path, filename)
        thumbnail_file.save(thumbnail_path)
        
        return jsonify({'success': True, 'filename': filename})
        
    except Exception as e:
        return jsonify({'success': False, 'message': f'Error saving thumbnail: {str(e)}'}), 500

# --- Stream History Routes ---
@app.route('/get_history', methods=['GET'])
def get_history_route():
    try:
        limit = request.args.get('limit', type=int)
        history = get_stream_history(limit)
        
        # Format history for frontend
        formatted_history = []
        for session in history:
            formatted_session = {
                'session_id': session['session_id'],
                'title': session.get('title', ''),
                'description': session.get('description', ''),
                'start_time': session.get('start_time'),
                'end_time': session.get('end_time'),
                'duration': session.get('duration'),
                'thumbnail_filename': session.get('thumbnail_filename'),
                'channels_used': session.get('channels_used', []),
                'live_urls': session.get('live_urls', {}),
                'viewer_stats': session.get('viewer_stats', {}),
                'status': session.get('status', 'completed'),
                'created_at': session.get('created_at')
            }
            formatted_history.append(formatted_session)
        
        return jsonify({'success': True, 'history': formatted_history})
        
    except Exception as e:
        return jsonify({'success': False, 'message': f'Error loading history: {str(e)}'}), 500

@app.route('/add_stream_session', methods=['POST'])
def add_stream_session_route():
    try:
        data = request.get_json()
        session_id = add_stream_session(data)
        
        return jsonify({
            'success': True,
            'message': 'Stream session added to history',
            'session_id': session_id
        })
        
    except Exception as e:
        return jsonify({'success': False, 'message': f'Error adding stream session: {str(e)}'}), 500

@app.route('/update_stream_session/<session_id>', methods=['POST'])
def update_stream_session_route(session_id):
    try:
        data = request.get_json()
        success = update_stream_session(session_id, data)
        
        if success:
            return jsonify({'success': True, 'message': 'Stream session updated'})
        else:
            return jsonify({'success': False, 'message': 'Session not found'}), 404
            
    except Exception as e:
        return jsonify({'success': False, 'message': f'Error updating stream session: {str(e)}'}), 500

@app.route('/delete_stream_session/<session_id>', methods=['POST'])
def delete_stream_session_route(session_id):
    try:
        success = delete_stream_session(session_id)
        
        if success:
            return jsonify({'success': True, 'message': 'Stream session deleted'})
        else:
            return jsonify({'success': False, 'message': 'Session not found'}), 404
            
    except Exception as e:
        return jsonify({'success': False, 'message': f'Error deleting stream session: {str(e)}'}), 500

@app.route('/history')
@login_required
def history_page():
    """Render the dedicated history page"""
    return render_template('history.html')

if __name__ == '__main__':
    app.run(debug=True, port=5005)

