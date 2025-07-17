# main.py
# This is the production code for your Cloud Run service.

import os
import base64
import re
import json
from datetime import datetime, timedelta, time
import pytz
import google.generativeai as genai
from flask import Flask, request
import google.auth
from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request
from googleapiclient.discovery import build
from google.cloud import secretmanager

# --- Flask App Initialization ---
app = Flask(__name__)

# --- Agent Configuration ---
SCOPES = ['https://mail.google.com/', 'https://www.googleapis.com/auth/calendar']
ET = pytz.timezone('America/New_York')
WORK_START_HOUR_ET = 9.5  # 9:30 AM
WORK_END_HOUR_ET = 18.0   # 6:00 PM

# --- Helper function to get secrets ---
def get_secret(project_id, secret_id, version_id="latest"):
    """Access the Secret Manager API to retrieve a secret."""
    try:
        client = secretmanager.SecretManagerServiceClient()
        name = f"projects/{project_id}/secrets/{secret_id}/versions/{version_id}"
        response = client.access_secret_version(request={"name": name})
        return response.payload.data.decode("UTF-8")
    except Exception as e:
        print(f"ERROR: Could not access secret: {secret_id}. Error: {e}")
        return None

# --- Get Project ID and Secrets ---
try:
    _, PROJECT_ID = google.auth.default()
    print(f"Successfully determined Project ID: {PROJECT_ID}")
except google.auth.exceptions.DefaultCredentialsError:
    print("Could not automatically determine project ID. Is this running locally?")
    PROJECT_ID = None

# This now correctly reads the secret you exposed as an environment variable in Cloud Run
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY")


def authenticate_with_secrets():
    """Authenticates with Google APIs using credentials from Secret Manager."""
    creds = None
    if not PROJECT_ID:
        print("ERROR: GCP_PROJECT environment variable not set. Running locally?")
        return None

    # Fetch the contents of the token file from Secret Manager
    token_json_str = get_secret(PROJECT_ID, "agent-token-json")
    
    if not token_json_str:
        print("ERROR: Could not retrieve token from Secret Manager.")
        return None

    try:
        # Load the credentials directly from the secret's string content
        creds_info = json.loads(token_json_str)
        creds = Credentials.from_authorized_user_info(creds_info, SCOPES)
    except Exception as e:
        print(f"ERROR: Could not load credentials from secret data. Error: {e}")
        return None

    # Check if the token is valid or needs to be refreshed
    if creds and creds.expired and creds.refresh_token:
        try:
            print("Token expired, attempting to refresh...")
            creds.refresh(Request())
            # Note: A mechanism would be needed here to update the secret with the new token
            # if the refresh token is long-lived. For now, we proceed with the refreshed token.
            print("Token refreshed successfully for this session.")
        except Exception as e:
            print(f"ERROR: Could not refresh token. A new token may need to be generated manually. Error: {e}")
            return None
            
    return creds

def get_email_intent_with_ai(email_text):
    """Uses Gemini to parse the user's intent from the email."""
    if not GEMINI_API_KEY:
        print("WARN: Gemini API key is not configured. Using fallback (60 min default).")
        return {'duration': 60, 'day_preference': None, 'time_of_day': None}
        
    try:
        genai.configure(api_key=GEMINI_API_KEY)
        model = genai.GenerativeModel('gemini-pro')
        prompt = f"""
        Read the following email snippet and extract the user's scheduling preferences.
        Respond with a JSON object containing three keys: "duration", "day_preference", and "time_of_day".
        - "duration" should be an integer in minutes (e.g., 30 or 60). Default to 60 if not specified.
        - "day_preference" should be the requested day of the week (e.g., "Monday", "Wednesday", "Friday") or null if not specified.
        - "time_of_day" should be "morning", "afternoon", or null if not specified. "Morning" is before 12 PM. "Afternoon" is 12 PM or later.
        Email: "{email_text}"
        JSON:
        """
        response = model.generate_content(prompt)
        # Clean up the response to get a valid JSON string
        json_str = response.text.strip().replace('```json', '').replace('```', '').strip()
        return json.loads(json_str)
    except Exception as e:
        print(f"AI parsing failed: {e}. Using default values.")
        return {'duration': 60, 'day_preference': None, 'time_of_day': None}

def find_available_slots(service, calendar_id, preferences):
    """Finds available slots based on AI-parsed preferences."""
    duration_minutes = preferences.get('duration', 60)
    day_preference = preferences.get('day_preference')
    time_of_day = preferences.get('time_of_day')

    now_utc = datetime.utcnow().replace(tzinfo=pytz.utc)
    now_et = now_utc.astimezone(ET)
    
    time_min_utc = now_utc.isoformat()
    time_max_utc = (now_utc + timedelta(days=14)).isoformat() # Look 14 days ahead

    events_result = service.events().list(calendarId=calendar_id, timeMin=time_min_utc,
                                          timeMax=time_max_utc, singleEvents=True,
                                          orderBy='startTime').execute()
    busy_slots = events_result.get('items', [])

    available_slots = []
    found_days = set()
    
    morning_end = time(12, 0)
    afternoon_start = time(12, 0)
    
    weekday_map = {
        'monday': 0, 'tuesday': 1, 'wednesday': 2, 'thursday': 3,
        'friday': 4, 'saturday': 5, 'sunday': 6
    }
    target_weekday = weekday_map.get(day_preference.lower()) if day_preference else None

    for day_offset in range(1, 15):
        if len(available_slots) >= 3:
            break
            
        day_to_check = (now_et + timedelta(days=day_offset))
        
        # Skip if a specific day was requested and this isn't it
        if target_weekday is not None and day_to_check.weekday() != target_weekday:
            continue

        workday_start_et = ET.localize(datetime.combine(day_to_check.date(), time())) + timedelta(hours=WORK_START_HOUR_ET)
        workday_end_et = ET.localize(datetime.combine(day_to_check.date(), time())) + timedelta(hours=WORK_END_HOUR_ET)
        
        # Adjust search window based on time_of_day preference
        if time_of_day == "morning":
            workday_end_et = min(workday_end_et, ET.localize(datetime.combine(day_to_check.date(), morning_end)))
        elif time_of_day == "afternoon":
            workday_start_et = max(workday_start_et, ET.localize(datetime.combine(day_to_check.date(), afternoon_start)))

        current_slot_start_et = workday_start_et
        
        while current_slot_start_et + timedelta(minutes=duration_minutes) <= workday_end_et:
            slot_start_et = current_slot_start_et
            slot_end_et = slot_start_et + timedelta(minutes=duration_minutes)
            
            slot_start_utc = slot_start_et.astimezone(pytz.utc)
            slot_end_utc = slot_end_et.astimezone(pytz.utc)

            is_available = True
            for event in busy_slots:
                event_start_str = event['start'].get('dateTime', event['start'].get('date'))
                event_end_str = event['end'].get('dateTime', event['end'].get('date'))
                if 'T' not in event_start_str: continue # Skip all-day events
                event_start_utc = datetime.fromisoformat(event_start_str.replace('Z', '+00:00'))
                event_end_utc = datetime.fromisoformat(event_end_str.replace('Z', '+00:00'))
                # Check for overlap
                if max(slot_start_utc, event_start_utc) < min(slot_end_utc, event_end_utc):
                    is_available = False
                    break
            
            # If the slot is free and we haven't found a slot for this day yet
            if is_available and day_to_check.date() not in found_days:
                available_slots.append({'slot': slot_start_et, 'duration': duration_minutes})
                found_days.add(day_to_check.date())
                # If no specific day was asked for, we're done once we have 3 days
                if not day_preference and len(found_days) >= 3:
                    break
            
            current_slot_start_et += timedelta(minutes=30) # Check next slot
            
    return available_slots[:3]

def create_email(sender, to, cc, subject, message_text):
  """Create a message for an email."""
  message = f"From: {sender}\nTo: {to}\nCc: {cc}\nSubject: {subject}\n\n{message_text}"
  return {'raw': base64.urlsafe_b64encode(message.encode()).decode()}

def send_email(service, user_id, message):
  """Send an email message."""
  try:
    message = (service.users().messages().send(userId=user_id, body=message).execute())
    return message
  except Exception as e:
    print(f'An error occurred while sending email: {e}')
    return None

def create_calendar_event(service, calendar_id, summary, start_time_et, duration_minutes, attendees):
    """Creates an event in the owner's calendar."""
    start_utc = start_time_et.astimezone(pytz.utc)
    end_utc = start_utc + timedelta(minutes=duration_minutes)
    
    event = {
        'summary': summary,
        'start': {'dateTime': start_utc.isoformat(), 'timeZone': 'America/New_York'},
        'end': {'dateTime': end_utc.isoformat(), 'timeZone': 'America/New_York'},
        'attendees': [{'email': email} for email in attendees],
    }
    created_event = service.events().insert(calendarId=calendar_id, body=event, sendNotifications=True).execute()
    print(f'Event created: {created_event.get("htmlLink")}')

@app.route('/', methods=['POST'])
def process_email_request():
    """Entry point for all requests, triggered by Pub/Sub."""
    envelope = request.get_json()
    if not envelope or 'message' not in envelope:
        print('Invalid Pub/Sub message format. This may be a health check.')
        return 'OK', 200 # Return 200 for health checks
    
    agent_email = 'anntaoai@gmail.com'
    owner_email = 'anntaod@gmail.com'
    owner_name = 'Anntao'

    creds = authenticate_with_secrets()
    if not creds:
        return "Authentication failed.", 500

    try:
        gmail_service = build('gmail', 'v1', credentials=creds)
        calendar_service = build('calendar', 'v3', credentials=creds)
    except Exception as e:
        print(f"CRITICAL: Failed to build API services. Error: {e}")
        return "Service build failed.", 500

    # New, more robust method to find the email
    try:
        # Instead of using history, search for the newest unread message.
        list_response = gmail_service.users().messages().list(userId='me', q='is:unread', maxResults=1).execute()
        if not list_response.get('messages'):
            print("No new unread messages found.")
            return "No unread messages.", 200
        
        msg_id = list_response['messages'][0]['id']
        message = gmail_service.users().messages().get(userId='me', id=msg_id).execute()
        
        headers = message['payload']['headers']
        subject = next((h['value'] for h in headers if h['name'].lower() == 'subject'), 'No Subject')
        snippet = message.get('snippet', '')

        original_to = next((h['value'] for h in headers if h['name'].lower() == 'to'), '')
        original_cc = next((h['value'] for h in headers if h['name'].lower() == 'cc'), '')
        if owner_email not in (original_to + original_cc):
             print(f"Owner ({owner_email}) not in recipients. Ignoring email.")
             gmail_service.users().messages().modify(userId='me', id=msg_id, body={'removeLabelIds': ['UNREAD']}).execute()
             return "Owner not in thread, request ignored.", 200

        if "Re:" in subject and "AI assistant" in snippet:
            body_data = message['payload']['parts'][0]['body'].get('data')
            body = base64.urlsafe_b64decode(body_data).decode('utf-8') if body_data else ""
            option_match = re.search(r'Option (\d)', body, re.IGNORECASE)
            if option_match:
                chosen_option = int(option_match.group(1))
                hidden_data_matches = re.findall(r'<!-- data: (.*?) -->', snippet)
                if len(hidden_data_matches) >= chosen_option:
                    event_data = json.loads(hidden_data_matches[chosen_option - 1])
                    start_time_et = ET.localize(datetime.fromisoformat(event_data['start']))
                    duration = event_data['duration']
                    
                    original_from = next((h['value'] for h in headers if h['name'].lower() == 'from'), '')
                    participants = [email.strip() for email in re.findall(r'[\w\.\+-]+@[\w\.-]+\.[\w\.-]+', original_from)]
                    attendees = [owner_email] + participants

                    create_calendar_event(calendar_service, owner_email, f"Meeting with {owner_name}", start_time_et, duration, attendees)
                    gmail_service.users().messages().modify(userId='me', id=msg_id, body={'removeLabelIds': ['UNREAD']}).execute()
                    print(f"Event scheduled with {', '.join(participants)}")
        
        else:
            preferences = get_email_intent_with_ai(snippet)
            available_slots = find_available_slots(calendar_service, owner_email, preferences)
            
            if available_slots:
                email_body = f"Hello,\n\nI'm the AI assistant for {owner_name}. I can help schedule a {preferences.get('duration', 60)}-minute meeting. Based on the request, here are available slots from {owner_name}'s calendar:\n\n"
                hidden_data_for_snippet = ""
                for i, slot_data in enumerate(available_slots):
                    slot_et = slot_data['slot']
                    email_body += f"Option {i+1}: {slot_et.strftime('%A, %B %d at %I:%M %p ET')}\n"
                    hidden_info = json.dumps({'start': slot_et.isoformat(), 'duration': slot_data['duration']})
                    hidden_data_for_snippet += f"<!-- data: {hidden_info} -->"

                email_body += f"\nPlease reply with the option number that works best for you (e.g., 'Option 2')."
                new_subject = f"Re: {subject} {hidden_data_for_snippet}"
                
                # Extract all emails from To and Cc fields
                all_emails = set(re.findall(r'<([^>]+)>', original_to + original_cc))
                all_emails.update(re.findall(r'[\w\.\+-]+@[\w\.-]+\.[\w\.-]+', original_to + original_cc))
                participants = [email for email in all_emails if email not in [agent_email, owner_email]]
                to_field = ", ".join(participants)
                cc_field = owner_email
                
                email_message = create_email(agent_email, to_field, cc_field, new_subject, email_body)
                send_email(gmail_service, 'me', email_message)
                # Mark the original message as read
                gmail_service.users().messages().modify(userId='me', id=msg_id, body={'removeLabelIds': ['UNREAD']}).execute()
                print(f"Sent time slot suggestions to {to_field}")
            else:
                 print("No available slots found matching the criteria.")

    except Exception as e:
        print(f"An error occurred during processing: {e}")
        return "An error occurred.", 500

    return "Processing complete.", 200

# This block is essential for the server to start.
if __name__ == "__main__":
    # Use the PORT environment variable provided by Cloud Run
    port = int(os.environ.get("PORT", 8080))
    app.run(debug=True, host='0.0.0.0', port=port)
