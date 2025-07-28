#!/usr/bin/env python3
"""
Gmail OAuth Token Generator for AI Email Agent
This script helps generate a fresh OAuth token for the Gmail API.
"""

import os
import json
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials

# Gmail API scopes
SCOPES = ['https://mail.google.com/', 'https://www.googleapis.com/auth/calendar']

def generate_token():
    """Generate a fresh OAuth token for Gmail API."""
    
    creds = None
    
    # Check if token.json exists
    if os.path.exists('token.json'):
        creds = Credentials.from_authorized_user_file('token.json', SCOPES)
    
    # If there are no (valid) credentials available, let the user log in
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            try:
                creds.refresh(Request())
                print("Token refreshed successfully!")
            except Exception as e:
                print(f"Token refresh failed: {e}")
                print("Generating new token...")
                creds = None
        
        if not creds:
            # You'll need to download the client configuration file from Google Cloud Console
            # and save it as 'credentials.json' in the same directory as this script
            if not os.path.exists('credentials.json'):
                print("ERROR: credentials.json not found!")
                print("Please download your OAuth 2.0 client configuration from Google Cloud Console")
                print("and save it as 'credentials.json' in this directory.")
                return None
            
            flow = InstalledAppFlow.from_client_secrets_file('credentials.json', SCOPES)
            creds = flow.run_local_server(port=0)
        
        # Save the credentials for the next run
        with open('token.json', 'w') as token:
            token.write(creds.to_json())
    
    # Convert to the format expected by Secret Manager
    token_data = {
        'token': creds.token,
        'refresh_token': creds.refresh_token,
        'token_uri': creds.token_uri,
        'client_id': creds.client_id,
        'client_secret': creds.client_secret,
        'scopes': creds.scopes
    }
    
    print("Token generated successfully!")
    print(f"Token expires at: {creds.expiry}")
    print("\nToken data for Secret Manager:")
    print(json.dumps(token_data, indent=2))
    
    return token_data

if __name__ == '__main__':
    print("Gmail OAuth Token Generator")
    print("=" * 30)
    print("This script will help you generate a fresh OAuth token for the Gmail API.")
    print("Make sure you have downloaded your OAuth 2.0 client configuration")
    print("from Google Cloud Console and saved it as 'credentials.json'")
    print()
    
    token_data = generate_token()
    
    if token_data:
        print("\n" + "=" * 50)
        print("NEXT STEPS:")
        print("1. Copy the JSON output above")
        print("2. Go to Google Cloud Console → Secret Manager")
        print("3. Find the 'agent-token-json' secret")
        print("4. Create a new version with the JSON data above")
        print("5. Deploy the updated code to Cloud Run")
        print("=" * 50) 