# YouTube Live Dashboard - Login System

## Overview
The YouTube Live Dashboard now includes a secure login system to protect access to the streaming tools and features.

## Login Credentials
- **Username**: `user`
- **Password**: `1234567890`

## Features
- **Secure Authentication**: Simple username/password authentication
- **Session Management**: Maintains login state across browser sessions
- **Protected Routes**: All main dashboard features require authentication
- **Automatic Redirects**: Unauthenticated users are redirected to login page
- **Clean Logout**: Properly clears all session data and YouTube tokens

## How to Use

### 1. Access the Application
- Start the server: `python app.py`
- Navigate to `http://localhost:5000`
- You'll be automatically redirected to the login page

### 2. Login
- Enter username: `user`
- Enter password: `1234567890`
- Click "Sign In"

### 3. Access Dashboard
- After successful login, you'll be redirected to the main dashboard
- All YouTube Live features are now accessible

### 4. Logout
- Click the "Logout" button in the sidebar
- You'll be redirected back to the login page
- All session data and YouTube tokens will be cleared

## Protected Routes
The following routes now require authentication:
- `/` - Main dashboard
- `/authorize` - YouTube account authorization
- `/instant_go_live` - Instant streaming
- `/multi_instant_go_live` - Multi-channel streaming
- `/create_shared_draft` - Draft creation
- `/history` - Stream history
- `/switch_account/<channel_id>` - Account switching

## Security Notes
- Credentials are stored in the application code (suitable for single-user applications)
- Sessions are managed using Flask's built-in session system
- YouTube OAuth tokens are properly revoked on logout
- All protected routes check authentication status

## Testing
Run the test script to verify login functionality:
```bash
python test_login.py
```

## File Structure
- `templates/login.html` - Login page template
- `app.py` - Updated with authentication logic
- `test_login.py` - Login functionality test script

## Customization
To change login credentials, modify the `VALID_CREDENTIALS` dictionary in `app.py`:
```python
VALID_CREDENTIALS = {
    'your_username': 'your_password'
}
```
