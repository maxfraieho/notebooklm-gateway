# Local Login Guide

This guide explains how to obtain `storage_state.json` for NotebookLM authentication.

## Prerequisites

- Python 3.10+
- A machine with GUI (desktop/laptop with browser)
- Google account with access to NotebookLM

## Steps

### 1. Install dependencies

```bash
pip install notebooklm-py playwright
playwright install chromium
```

### 2. Run login command

```bash
notebooklm login
```

This will:
- Open a Chromium browser window
- Navigate to Google login
- Wait for you to complete authentication

### 3. Complete Google login

- Sign in with your Google account
- Complete any 2FA if required
- Wait for the NotebookLM page to load

### 4. Get the storage_state.json

After successful login, the file `storage_state.json` will be created in your current directory.

**Location:** `./storage_state.json` (in the directory where you ran the command)

### 5. Upload to server

Option A: **Web interface**
- Open `http://your-server:8000/auth` in browser
- Upload the `storage_state.json` file

Option B: **API**
```bash
curl -X POST http://your-server:8000/auth/upload \
  -F "file=@storage_state.json"
```

### 6. Verify

```bash
curl http://your-server:8000/auth/status
```

Expected response:
```json
{
  "ok": true,
  "message": "Authentication valid",
  "notebook_count": 5
}
```

## Security Notes

- `storage_state.json` contains your Google session cookies
- **Never** commit this file to version control
- **Never** share this file with others
- Session may expire; re-run `notebooklm login` if needed
- Keep the file in a secure location

## Troubleshooting

### "Authentication failed" after upload

1. Session may have expired - re-run `notebooklm login`
2. Ensure you logged into the correct Google account
3. Check if NotebookLM is available in your region

### Browser doesn't open

```bash
# Install browser dependencies (Linux)
playwright install-deps chromium
```

### "NotebookLM not available"

NotebookLM may not be available in your region or for your account type.
Try with a Google One subscription or US-based account.
