# main.py
# This is the production code for your Cloud Run service.
# Version: 2025-07-17 - Added debugging for hidden data extraction

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
from google.cloud import firestore
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import time as sleep_timer
import random
import re
from dateutil import parser as dtparser

# --- Flask App Initialization ---
app = Flask(__name__)

# --- Agent Configuration ---
SCOPES = ['https://mail.google.com/', 'https://www.googleapis.com/auth/calendar']
ET = pytz.timezone('America/New_York')
WORK_START_HOUR_ET = 9.5  # 9:30 AM
WORK_END_HOUR_ET = 18.0   # 6:00 PM
AGENT_DISPLAY_NAME = "Anntao's AI Assistant"

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

def authenticate_with_secrets(project_id):
    """Authenticates with Google APIs using credentials from Secret Manager."""
    token_json_str = get_secret(project_id, "agent-token-json")
    if not token_json_str:
        print("ERROR: Could not retrieve token from Secret Manager.")
        return None

    try:
        creds_info = json.loads(token_json_str)
        creds = Credentials.from_authorized_user_info(creds_info, SCOPES)
        if creds.expired and creds.refresh_token:
            print("Token expired, attempting to refresh...")
            creds.refresh(Request())
            print("Token refreshed successfully for this session.")
        return creds
    except Exception as e:
        print(f"ERROR: Could not load or refresh credentials. Error: {e}")
        return None

def get_conversation_intent_with_ai(email_thread_text, current_date_et, api_key):
    """Uses Gemini to determine the overall intent of the email thread."""
    if not api_key:
        print("WARN: Gemini API key is not configured. Cannot determine intent.")
        return {"intent": "error", "data": "API key missing"}

    try:
        genai.configure(api_key=api_key)
        model = genai.GenerativeModel('gemini-2.5-flash') 
        
        prompt = f"""
        Analyze the following email thread to determine the user's current intent. The current date is {current_date_et.strftime('%Y-%m-%d')}.

        There are four possible intents:
        1. "INITIAL_REQUEST": The user is starting a new request to schedule a meeting. Extract their preferences (duration, day_preference, time_of_day, start_date).
        2. "CONFIRMATION": The user is replying to confirm a specific time slot that was previously offered. Extract the exact ISO 8601 formatted string of the confirmed time.
        3. "DAY_CONFIRMATION": The user is confirming a specific day (e.g., "Tuesday works", "Monday is good") but not a specific time. Extract the day name and optionally a time preference.
        4. "OTHER": The email is not related to scheduling, or it's a negotiation where no specific time was chosen.

        The agent's previous suggestions are embedded in HTML comments like <!-- data: {{"start": "...", "duration": ...}} -->. Use these to identify if the current email is a reply to suggestions.

        IMPORTANT: 
        - For CONFIRMATION intent, the confirmed_start_time_iso must be in ISO 8601 format with timezone (e.g., "2024-01-15T14:30:00-05:00" for 2:30 PM ET). 
        - For DAY_CONFIRMATION intent, return the day name and optionally time_of_day preference.
        - If the user mentions a time without timezone, assume Eastern Time (ET).

        Respond with a JSON object with two keys: "intent" and "data".
        - If intent is "INITIAL_REQUEST", "data" should be a JSON object with scheduling preferences.
        - If intent is "CONFIRMATION", "data" should be a JSON object with the key "confirmed_start_time_iso" containing the exact time in ISO 8601 format.
        - If intent is "DAY_CONFIRMATION", "data" should be a JSON object with keys "day_name" (e.g., "tuesday", "monday") and optionally "time_of_day" (e.g., "morning", "afternoon").
        - If intent is "OTHER", "data" can be null.

        Email Thread:
        \"\"\"
        {email_thread_text}
        \"\"\"

        JSON:
        """
        response = model.generate_content(prompt)
        print(f"AI intent analysis response: {response.text}")
        json_str = response.text.strip().replace('```json', '').replace('```', '').strip()
        return json.loads(json_str)
    except Exception as e:
        print(f"AI intent analysis failed: {e}")
        return {"intent": "error", "data": str(e)}


def find_available_slots(service, calendar_id, preferences):
    """Finds available slots based on AI-parsed preferences, skipping weekends."""
    duration_minutes = preferences.get('duration') or 60
    day_preference = preferences.get('day_preference')
    
    # --- FIX: Handle case where AI returns a list for day_preference ---
    if isinstance(day_preference, list):
        day_preference = day_preference[0] if day_preference else None

    time_of_day = preferences.get('time_of_day')
    start_date_str = preferences.get('start_date')

    now_utc = datetime.utcnow().replace(tzinfo=pytz.utc)
    now_et = now_utc.astimezone(ET)
    
    search_start_date_et = now_et
    if start_date_str:
        try:
            parsed_date = datetime.strptime(start_date_str, '%Y-%m-%d')
            search_start_date_et = ET.localize(parsed_date)
        except (ValueError, TypeError):
            print(f"AI provided an invalid start_date format: {start_date_str}. Using today.")

    time_min_utc = search_start_date_et.astimezone(pytz.utc).isoformat()
    time_max_utc = (search_start_date_et.astimezone(pytz.utc) + timedelta(days=14)).isoformat()

    events_result = service.events().list(calendarId=calendar_id, timeMin=time_min_utc,
                                          timeMax=time_max_utc, singleEvents=True,
                                          orderBy='startTime').execute()
    busy_slots = events_result.get('items', [])

    available_slots = []
    found_days = set()
    
    morning_end = time(12, 0)
    afternoon_start = time(12, 0)
    
    weekday_map = {
        'monday': 0, 'tuesday': 1, 'wednesday': 2, 'thursday': 3, 'friday': 4
    }
    target_weekday = weekday_map.get(day_preference.lower()) if day_preference else None
    
    for day_offset in range(14):
        if len(available_slots) >= 3:
            break
            
        day_to_check_naive = (search_start_date_et + timedelta(days=day_offset)).date()
        
        if day_to_check_naive < now_et.date():
            continue

        if day_to_check_naive.weekday() >= 5: 
            continue
            
        if target_weekday is not None and day_to_check_naive.weekday() != target_weekday:
            continue

        workday_start_et = ET.localize(datetime.combine(day_to_check_naive, time(int(WORK_START_HOUR_ET), int((WORK_START_HOUR_ET*60)%60))))
        workday_end_et = ET.localize(datetime.combine(day_to_check_naive, time(int(WORK_END_HOUR_ET), int((WORK_END_HOUR_ET*60)%60))))
        
        if time_of_day == "morning":
            workday_end_et = min(workday_end_et, ET.localize(datetime.combine(day_to_check_naive, morning_end)))
        elif time_of_day == "afternoon":
            workday_start_et = max(workday_start_et, ET.localize(datetime.combine(day_to_check_naive, afternoon_start)))

        current_slot_start_et = max(workday_start_et, now_et + timedelta(minutes=5))
        
        while current_slot_start_et + timedelta(minutes=duration_minutes) <= workday_end_et:
            slot_start_et = current_slot_start_et
            slot_end_et = slot_start_et + timedelta(minutes=duration_minutes)
            
            is_available = True
            for event in busy_slots:
                event_start_str = event['start'].get('dateTime', event['start'].get('date'))
                event_end_str = event['end'].get('dateTime', event['end'].get('date'))
                if 'T' not in event_start_str: continue 
                event_start_utc = datetime.fromisoformat(event_start_str.replace('Z', '+00:00'))
                event_end_utc = datetime.fromisoformat(event_end_str.replace('Z', '+00:00'))
                if max(slot_start_et.astimezone(pytz.utc), event_start_utc) < min(slot_end_et.astimezone(pytz.utc), event_end_utc):
                    is_available = False
                    break
            
            if is_available and day_to_check_naive not in found_days:
                available_slots.append({'slot': slot_start_et, 'duration': duration_minutes})
                found_days.add(day_to_check_naive)
                if not day_preference and not start_date_str and len(found_days) >= 3:
                    break
            
            current_slot_start_et += timedelta(minutes=30)
            
    return available_slots[:3]

def create_threaded_email(sender, to, cc, subject, html_body, in_reply_to, references):
    """Creates a MIME message that will reply in the same thread."""
    message = MIMEMultipart('alternative')
    message['to'] = to
    # --- PATCH: Set display name in From header ---
    message['from'] = f"{AGENT_DISPLAY_NAME} <{sender}>"
    message['cc'] = cc
    message['subject'] = subject
    message['In-Reply-To'] = in_reply_to
    message['References'] = references
    message['X-Agent-Processed'] = 'true'
    message.attach(MIMEText(html_body, 'html'))
    return {'raw': base64.urlsafe_b64encode(message.as_bytes()).decode()}

def send_email(service, user_id, message, thread_id=None):
  """Send an email message, optionally in a specific thread."""
  try:
    if thread_id:
      message['threadId'] = thread_id
    sent = (service.users().messages().send(userId=user_id, body=message).execute())
    return sent
  except Exception as e:
    print(f'An error occurred while sending email: {e}')
    return None

def create_calendar_event(service, calendar_id, summary, start_time_et, duration_minutes, attendees):
    """Creates an event in the owner's calendar and emails all attendees."""
    start_utc = start_time_et.astimezone(pytz.utc)
    end_utc = start_utc + timedelta(minutes=duration_minutes)
    event = {
        'summary': summary,
        'start': {'dateTime': start_utc.isoformat(), 'timeZone': 'America/New_York'},
        'end': {'dateTime': end_utc.isoformat(), 'timeZone': 'America/New_York'},
        'attendees': [{'email': email} for email in attendees],
        'reminders': {'useDefault': True},
    }
    created_event = service.events().insert(calendarId=calendar_id, body=event, sendUpdates='all').execute()
    print(f'Event created: {created_event.get("htmlLink")}')

def get_full_email_body(payload):
    """
    Recursively decodes and extracts all plain text and html content from an email payload.
    This is necessary to find the hidden data comments in replies.
    """
    body = ""
    
    # Handle multipart messages
    if 'parts' in payload:
        for part in payload['parts']:
            body += get_full_email_body(part)
    
    # Handle single part messages
    elif payload.get('body') and payload['body'].get('data'):
        data = payload['body']['data']
        try:
            decoded = base64.urlsafe_b64decode(data).decode('utf-8', errors='ignore')
            body += decoded
            print(f"Decoded email part: {len(decoded)} chars")
        except Exception as e:
            print(f"Could not decode email part: {e}")
    
    # Handle messages with body but no data (sometimes happens)
    elif payload.get('body') and payload['body'].get('data') is None:
        print("Email part has body but no data field")
    
    # Debug: print payload structure for troubleshooting
    if not body and 'mimeType' in payload:
        print(f"Email part MIME type: {payload['mimeType']}")
    
    return body

def maybe_refresh_gmail_watch(gmail_service, db, project_id):
    """Check and refresh Gmail watch if expired or about to expire."""
    topic_name = f"projects/{project_id}/topics/gmail-new-email"
    doc_ref = db.collection('gmail_watch').document('expiration')
    doc = doc_ref.get()
    now_ms = int(datetime.utcnow().timestamp() * 1000)
    needs_refresh = True
    if doc.exists:
        expiration = doc.to_dict().get('expiration')
        if expiration and expiration > now_ms + 24*60*60*1000:
            needs_refresh = False
    if needs_refresh:
        print("Refreshing Gmail watch...")
        response = gmail_service.users().watch(userId='me', body={"topicName": topic_name}).execute()
        new_expiration = int(response.get('expiration', 0))
        doc_ref.set({'expiration': new_expiration})
        print(f"Watch refreshed, new expiration: {new_expiration}")

@app.route('/', methods=['POST'])
def process_email_request():
    """Entry point for all requests, triggered by Pub/Sub."""
    
    envelope = request.get_json()
    if not envelope or 'message' not in envelope:
        print('Invalid Pub/Sub message format. This may be a health check.')
        return 'OK', 200
    
    try:
        _, project_id = google.auth.default()
        db = firestore.Client(project=project_id)
    except google.auth.exceptions.DefaultCredentialsError:
        print("ERROR: Could not automatically determine project ID.")
        return "Internal Server Error", 500

    gemini_api_key = os.environ.get("GEMINI_API_KEY")
    
    # --- PATCH: Auto-refresh Gmail watch if needed ---
    creds = authenticate_with_secrets(project_id)
    if not creds:
        return "Authentication failed.", 500
    gmail_service = build('gmail', 'v1', credentials=creds)
    maybe_refresh_gmail_watch(gmail_service, db, project_id)

    try:
        data = json.loads(base64.b64decode(envelope['message']['data']).decode('utf-8'))
        history_id = str(data['historyId'])
        doc_ref = db.collection('processed_history').document(history_id)

        # --- PATCH: Use Firestore transaction for atomic deduplication ---
        @firestore.transactional
        def dedup_transaction(transaction, doc_ref):
            snapshot = doc_ref.get(transaction=transaction)
            if snapshot.exists:
                print(f"Duplicate historyId detected (transaction): {history_id}. Ignoring.")
                return False
            transaction.set(doc_ref, {'timestamp': firestore.SERVER_TIMESTAMP})
            return True

        dedup_result = dedup_transaction(db.transaction(), doc_ref)
        if not dedup_result:
            return "Duplicate message", 200

    except Exception as e:
        print(f"Firestore deduplication check failed: {e}")
        return "Internal Server Error", 500

    sleep_timer.sleep(5)
    
    # Remove hardcoded values and fetch from Secret Manager
    agent_email = get_secret(project_id, "agent-email")
    owner_email = get_secret(project_id, "owner-email")
    owner_name = get_secret(project_id, "owner-name")

    creds = authenticate_with_secrets(project_id)
    if not creds:
        return "Authentication failed.", 500

    try:
        gmail_service = build('gmail', 'v1', credentials=creds)
        calendar_service = build('calendar', 'v3', credentials=creds)
    except Exception as e:
        print(f"CRITICAL: Failed to build API services. Error: {e}")
        return "Service build failed.", 500

    try:
        list_response = gmail_service.users().messages().list(userId='me', q='is:unread', maxResults=1).execute()
        if not list_response.get('messages'):
            print("No new unread messages found.")
            return "No unread messages.", 200
        
        msg_id = list_response['messages'][0]['id']
        
        gmail_service.users().messages().modify(userId='me', id=msg_id, body={'removeLabelIds': ['UNREAD']}).execute()
        
        message = gmail_service.users().messages().get(userId='me', id=msg_id, format='full').execute()
        
        headers = message['payload']['headers']
        is_agent_sent = any(h['name'] == 'X-Agent-Processed' and h['value'] == 'true' for h in headers)
        if is_agent_sent:
            print(f"Ignoring agent's own message: {msg_id}")
            return "Agent message ignored.", 200

        subject = next((h['value'] for h in headers if h['name'].lower() == 'subject'), 'No Subject')
        
        # Get the current message content
        current_message_text = get_full_email_body(message['payload'])
        print(f"Current message text length: {len(current_message_text)}")
        print(f"Current message preview (first 500 chars): {current_message_text[:500]}")
        
        # Get the full thread content by fetching the thread
        thread_id = message.get('threadId')
        full_thread_text = current_message_text  # Start with current message
        
        if thread_id:
            try:
                thread = gmail_service.users().threads().get(userId='me', id=thread_id).execute()
                print(f"Thread has {len(thread.get('messages', []))} messages")
                
                # Combine all messages in the thread
                for msg in thread.get('messages', []):
                    if msg['id'] != msg_id:  # Skip current message (already processed)
                        thread_msg_text = get_full_email_body(msg['payload'])
                        full_thread_text += "\n\n--- THREAD MESSAGE ---\n\n" + thread_msg_text
                        print(f"Added thread message: {len(thread_msg_text)} chars")
            except Exception as e:
                print(f"Could not fetch full thread: {e}")
        
        print(f"Full thread text length: {len(full_thread_text)}")
        print(f"Full thread preview (first 500 chars): {full_thread_text[:500]}")
        
        message_id_header = next((h['value'] for h in headers if h['name'].lower() == 'message-id'), None)
        references_header = next((h['value'] for h in headers if h['name'].lower() == 'references'), '')
        new_references = f"{references_header} {message_id_header}".strip()

        original_to = next((h['value'] for h in headers if h['name'].lower() == 'to'), '')
        original_cc = next((h['value'] for h in headers if h['name'].lower() == 'cc'), '')
        original_from_header = next((h['value'] for h in headers if h['name'].lower() == 'from'), '')
        owner_email = owner_email or ""
        original_to = original_to or ""
        original_cc = original_cc or ""
        original_from_header = original_from_header or ""
        print(f"owner_email: {owner_email}")
        print(f"original_to: {original_to}")
        print(f"original_cc: {original_cc}")
        print(f"original_from_header: {original_from_header}")
        if owner_email not in (original_to + original_cc + original_from_header):
            print(f"Owner ({owner_email}) not in participants. Ignoring email.")
            return "Owner not in thread, request ignored.", 200
        
        intent_response = get_conversation_intent_with_ai(full_thread_text, datetime.now(ET), gemini_api_key)
        intent = intent_response.get("intent")
        intent_data = intent_response.get("data")
        print(f"Intent detected: {intent}, proceeding to slot generation...")

        # --- PATCH: Add robust debug and exception logging for INITIAL_REQUEST ---
        if intent == "INITIAL_REQUEST":
            try:
                print("[DEBUG] INITIAL_REQUEST: About to generate slots...")
                preferences = intent_data or {}
                available_slots = find_available_slots(calendar_service, owner_email, preferences)
                print(f"[DEBUG] INITIAL_REQUEST: Available slots: {available_slots}")

                all_emails_str = original_to + "," + original_cc + "," + original_from_header
                all_emails = list(set(re.findall(r'[\w\.+-]+@[\w\.-]+\.[\w\.-]+', all_emails_str)))
                participants = [email for email in all_emails if email not in [agent_email, owner_email]]
                to_field = ", ".join(participants)
                cc_field = owner_email

                print(f"[DEBUG] INITIAL_REQUEST: To field: {to_field}, CC field: {cc_field}")

                if not participants:
                    print("[DEBUG] INITIAL_REQUEST: No valid participants found for To field. Using original sender as recipient.")
                    sender_match = re.search(r'[\w\.+-]+@[\w\.-]+\.[\w\.-]+', original_from_header)
                    if sender_match:
                        to_field = sender_match.group(0)
                    else:
                        print("[DEBUG] INITIAL_REQUEST: Could not extract sender email. Aborting send.")
                        return "No valid recipient found.", 500

                # Compose slots text and hidden data
                slots_text = ""
                hidden_data_for_body = ""
                for i, slot_data in enumerate(available_slots):
                    slot_et = slot_data['slot']
                    slots_text += f"- {slot_et.strftime('%A, %B %d at %I:%M %p ET')}\n"
                    hidden_info = json.dumps({'start': slot_et.isoformat(), 'duration': slot_data['duration']})
                    hidden_data_for_body += f"<!-- data: {hidden_info} -->\n"
                    hidden_data_for_body += f'<span style="display:none;">SLOT_DATA:{hidden_info}</span>\n'

                # --- PATCH: Extract recipient first name from signature if present ---
                # Try to find a signature block in the current message
                signature_match = re.search(r'-- ?\\n([A-Za-z]+)', current_message_text)
                if signature_match:
                    greeting_name = signature_match.group(1)
                else:
                    # Fallback to previous logic (extract from email headers)
                    recipient_names = []
                    for email in participants:
                        try:
                            # Use a robust regex for name extraction, ensure all parentheses are closed
                            pattern = r'([\w\s\"\']+)\s*<\s*' + re.escape(email) + r'\s*>'
                            name_match = re.search(pattern, original_to + "," + original_cc + "," + original_from_header, re.IGNORECASE)
                        except Exception as e:
                            print(f"Regex error in recipient name extraction: {e}")
                            name_match = None
                        if name_match:
                            name = name_match.group(1).replace('"', '').replace("'", '').strip()
                            recipient_names.append(name)
                        else:
                            recipient_names.append(email)
                    greeting_name = recipient_names[0] if recipient_names else ""
                if not greeting_name or greeting_name.lower() == 'hi':
                    greeting_name = "Hi"

                # --- In all agent email composition (INITIAL_REQUEST, OTHER, etc):
                # 1. Remove greeting_template, greeting_name, and Gemini greeting prompt logic.
                # 2. Only ask Gemini for the main body (slot list, instructions, etc.).
                # 3. Always prepend 'Hi<br><br>' to the email body in the HTML.
                prompt = f"""
                You are a helpful AI assistant for {owner_name}.
                Write a brief, friendly, and natural-sounding email to propose meeting times. Do NOT include a greeting or recipient name. The available time slots are:
                {slots_text}
                Your response should be conversational and not robotic. Do NOT include a subject line or greeting. End by saying something like, 'Let me know if any of these work for you!'
                """
                genai.configure(api_key=gemini_api_key)
                model = genai.GenerativeModel('gemini-2.5-flash')
                email_response = model.generate_content(prompt)
                email_body_text = email_response.text

                # --- PATCH: Professional agent signature ---
                html_body = f"""
                <html><body>
                <p>Hi<br><br>{email_body_text.replace(os.linesep, '<br>')}</p>
                {hidden_data_for_body}
                <div style='margin-top:32px; margin-bottom:8px; border-top:1px solid #e0e0e0;'></div>
                <div style='color:#222; font-size:13px; font-family:sans-serif; margin-top:8px;'>
                  <strong>Anntao's AI Assistant</strong><br>
                  <span style='color:#888;'>on behalf of {owner_name}</span>
                </div>
                </body></html>
                """

                clean_subject = f"Re: {subject.replace('Re: ', '')}"
                email_message = create_threaded_email(agent_email, to_field, cc_field, clean_subject, html_body, in_reply_to=message_id_header, references=new_references)
                send_email(gmail_service, 'me', email_message, thread_id=thread_id)
                print(f"[DEBUG] INITIAL_REQUEST: Sent time slot suggestions to {to_field}")
                gmail_service.users().messages().modify(userId='me', id=msg_id, body={'removeLabelIds': ['UNREAD']}).execute()
                print(f"[DEBUG] INITIAL_REQUEST: Marked message {msg_id} as read and set historyId {history_id}")
            except Exception as e:
                import traceback
                print(f"[ERROR] Exception in INITIAL_REQUEST branch: {e}")
                traceback.print_exc()
                return "Error in INITIAL_REQUEST", 500

        elif intent == "CONFIRMATION":
            print("AI detected CONFIRMATION intent.")
            confirmed_start_time_iso = None
            if intent_data and isinstance(intent_data, dict):
                confirmed_start_time_iso = intent_data.get('confirmed_start_time_iso')

            if confirmed_start_time_iso:
                print(f"AI returned confirmed time: {confirmed_start_time_iso}")
                # Search for both HTML comments and invisible spans
                hidden_data_matches = re.findall(r'<!-- data: (.*?) -->', full_thread_text)
                slot_data_matches = re.findall(r'SLOT_DATA:(.*?)</span>', full_thread_text)
                
                # Combine both types of matches
                all_hidden_matches = hidden_data_matches + slot_data_matches
                print(f"Found {len(hidden_data_matches)} HTML comment matches and {len(slot_data_matches)} span matches")
                print(f"Total hidden data matches: {len(all_hidden_matches)}")
                
                # Debug: search for any HTML comments
                all_comments = re.findall(r'<!--.*?-->', full_thread_text)
                print(f"Total HTML comments found: {len(all_comments)}")
                for i, comment in enumerate(all_comments[:3]):  # Show first 3 comments
                    print(f"Comment {i+1}: {comment}")
                
                # Debug: search for "data:" anywhere in the text
                all_comments = re.findall(r'<!--.*?-->', full_thread_text)
                print(f"Total HTML comments found: {len(all_comments)}")
                for i, comment in enumerate(all_comments[:3]):  # Show first 3 comments
                    print(f"Comment {i+1}: {comment}")
                
                duration = 60 
                found_match = False
                
                # Parse the confirmed time from AI
                try:
                    confirmed_dt = datetime.fromisoformat(confirmed_start_time_iso)
                    if confirmed_dt.tzinfo is None:
                        # If no timezone info, assume it's in ET
                        confirmed_dt = ET.localize(confirmed_dt)
                    else:
                        # Convert to ET
                        confirmed_dt = confirmed_dt.astimezone(ET)
                    confirmed_dt_rounded = confirmed_dt.replace(second=0, microsecond=0)
                    print(f"Parsed confirmed time (ET): {confirmed_dt_rounded}")
                except Exception as e:
                    print(f"Error parsing confirmed time: {e}")
                    return "Error parsing confirmed time", 500

                for i, hidden_info_str in enumerate(all_hidden_matches):
                    try:
                        event_data = json.loads(hidden_info_str)
                        print(f"Hidden data {i+1}: {event_data}")
                        
                        event_dt = datetime.fromisoformat(event_data['start'])
                        if event_dt.tzinfo is None:
                            # If no timezone info, assume it's in ET
                            event_dt = ET.localize(event_dt)
                        else:
                            # Convert to ET
                            event_dt = event_dt.astimezone(ET)
                        event_dt_rounded = event_dt.replace(second=0, microsecond=0)
                        
                        # --- PATCH: Robust slot confirmation matching (±5 min) ---
                        delta = abs((confirmed_dt_rounded - event_dt_rounded).total_seconds())
                        print(f"Comparing: AI='{confirmed_dt_rounded}' vs Option='{event_dt_rounded}' (delta: {delta} seconds)")
                        if delta <= 5 * 60:
                            duration = event_data['duration']
                            found_match = True
                            print(f"Found matching slot! Duration: {duration} minutes")
                            break
                    except Exception as e:
                        print(f"Error parsing hidden data {i+1}: {e}")
                        continue
                
                if found_match:
                    # Use the confirmed datetime directly since we already parsed it
                    start_time_et = confirmed_dt
                    all_emails_str = original_to + "," + original_cc + "," + original_from_header
                    attendees = list(set(re.findall(r'[\w\.\+-]+@[\w\.-]+\.[\w\.-]+', all_emails_str)))
                    attendees = [email for email in attendees if email != agent_email]
                    if owner_email not in attendees:
                        attendees.append(owner_email)

                    create_calendar_event(calendar_service, owner_email, f"Meeting: {subject.replace('Re: ', '')}", start_time_et, duration, attendees)
                    print(f"Event scheduled with {', '.join(attendees)}")
                    doc_ref.set({'timestamp': firestore.SERVER_TIMESTAMP})
                    gmail_service.users().messages().modify(userId='me', id=msg_id, body={'removeLabelIds': ['UNREAD']}).execute()
                    print(f"Marked message {msg_id} as read and set historyId {history_id}")
                else:
                    print(f"AI confirmed a time ({confirmed_start_time_iso}), but it was not one of the options offered. Ignoring.")
                    print(f"Available options were: {[datetime.fromisoformat(json.loads(match)['start']).astimezone(ET).strftime('%Y-%m-%d %H:%M ET') for match in hidden_data_matches]}")

        elif intent == "DAY_CONFIRMATION":
            print("AI detected DAY_CONFIRMATION intent.")
            day_name = None
            time_of_day = None
            if intent_data and isinstance(intent_data, dict):
                day_name = intent_data.get('day_name')
                time_of_day = intent_data.get('time_of_day')

            if day_name:
                print(f"User confirmed day: {day_name}, time preference: {time_of_day}")
                # Search for both HTML comments and invisible spans
                hidden_data_matches = re.findall(r'<!-- data: (.*?) -->', full_thread_text)
                slot_data_matches = re.findall(r'SLOT_DATA:(.*?)</span>', full_thread_text)
                
                # Combine both types of matches
                all_hidden_matches = hidden_data_matches + slot_data_matches
                print(f"Found {len(hidden_data_matches)} HTML comment matches and {len(slot_data_matches)} span matches")
                print(f"Total hidden data matches: {len(all_hidden_matches)}")
                
                # Find the next occurrence of this day
                weekday_map = {
                    'monday': 0, 'tuesday': 1, 'wednesday': 2, 'thursday': 3, 'friday': 4
                }
                target_weekday = weekday_map.get(day_name.lower())
                
                if target_weekday is None:
                    print(f"Invalid day name: {day_name}")
                    return "Invalid day name", 400
                
                # Find matching slots for this day
                matching_slots = []
                for hidden_info_str in all_hidden_matches:
                    try:
                        event_data = json.loads(hidden_info_str)
                        event_dt = datetime.fromisoformat(event_data['start'])
                        if event_dt.tzinfo is None:
                            event_dt = ET.localize(event_dt)
                        else:
                            event_dt = event_dt.astimezone(ET)
                        
                        # Check if this slot is on the target day
                        if event_dt.weekday() == target_weekday:
                            # If user specified time_of_day preference, filter by that
                            if time_of_day:
                                hour = event_dt.hour
                                if time_of_day == "morning" and hour >= 12:
                                    continue
                                elif time_of_day == "afternoon" and hour < 12:
                                    continue
                            
                            matching_slots.append({
                                'datetime': event_dt,
                                'duration': event_data['duration']
                            })
                    except Exception as e:
                        print(f"Error parsing hidden data: {e}")
                        continue
                
                if matching_slots:
                    # Sort by time and take the first one
                    matching_slots.sort(key=lambda x: x['datetime'])
                    selected_slot = matching_slots[0]
                    
                    print(f"Selected slot for {day_name}: {selected_slot['datetime'].strftime('%A, %B %d at %I:%M %p ET')}")
                    
                    # Schedule the meeting
                    all_emails_str = original_to + "," + original_cc + "," + original_from_header
                    attendees = list(set(re.findall(r'[\w\.\+-]+@[\w\.-]+\.[\w\.-]+', all_emails_str)))
                    attendees = [email for email in attendees if email != agent_email]
                    if owner_email not in attendees:
                        attendees.append(owner_email)

                    create_calendar_event(calendar_service, owner_email, f"Meeting: {subject.replace('Re: ', '')}", 
                                       selected_slot['datetime'], selected_slot['duration'], attendees)
                    print(f"Event scheduled with {', '.join(attendees)}")
                    doc_ref.set({'timestamp': firestore.SERVER_TIMESTAMP})
                    gmail_service.users().messages().modify(userId='me', id=msg_id, body={'removeLabelIds': ['UNREAD']}).execute()
                    print(f"Marked message {msg_id} as read and set historyId {history_id}")
                else:
                    print(f"No available slots found for {day_name} with time preference: {time_of_day}")
            else:
                print("AI detected DAY_CONFIRMATION but no day_name provided")

        # --- IMPROVEMENT: Handle 'none of these work' replies ---
        elif intent == "OTHER":
            print("AI detected OTHER intent. Checking for new preferences.")
            # Try to extract new preferences from the AI (reuse INITIAL_REQUEST logic)
            preferences = {'duration': 60}
            # Ask Gemini to extract new preferences if present, including time and time zone
            try:
                genai.configure(api_key=gemini_api_key)
                model = genai.GenerativeModel('gemini-2.5-flash')
                pref_prompt = f"""
                The user replied that none of the offered times work, or is proposing a new time. Please extract any new preferences for meeting time (such as preferred days, times, durations, or specific times) from the following email. If the user mentions a specific time (e.g., '4pm Paris'), extract both the time and the time zone/city if present. If no new preferences are found, return an empty object.
                Email:
                '''
                {current_message_text}
                '''
                Respond with a JSON object with possible keys: duration, day_preference, time_of_day, start_date, specific_time (ISO 8601), time_zone (IANA tz name or city).
                """
                pref_response = model.generate_content(pref_prompt)
                print(f"AI preference extraction response: {pref_response.text}")
                pref_json = pref_response.text.strip().replace('```json', '').replace('```', '').strip()
                new_prefs = json.loads(pref_json)
                if new_prefs:
                    preferences.update(new_prefs)
            except Exception as e:
                print(f"Could not extract new preferences: {e}")
            print(f"Preferences for slot search: {preferences}")

            # --- PATCH: Handle specific_time and time_zone conversion ---
            user_time_et = None
            if preferences.get('specific_time'):
                user_time_str = preferences['specific_time']
                if not isinstance(user_time_str, str):
                    user_time_str = str(user_time_str)
                user_tz = preferences.get('time_zone', 'America/New_York')
                if not isinstance(user_tz, str):
                    user_tz = str(user_tz)
                try:
                    dt = dtparser.parse(user_time_str)
                    if dt.tzinfo is None:
                        # Try to localize to user_tz if possible
                        try:
                            if not isinstance(user_tz, str):
                                user_tz = str(user_tz)
                            tz = pytz.timezone(user_tz)
                        except Exception:
                            # Try to map city to tz
                            city_map = {'Paris': 'Europe/Paris', 'London': 'Europe/London', 'New York': 'America/New_York'}
                            tz_name = city_map.get(str(user_tz), 'America/New_York')
                            try:
                                tz = pytz.timezone(str(tz_name))
                            except Exception:
                                tz = pytz.timezone('America/New_York')
                        dt = tz.localize(dt)
                    user_time_et = dt.astimezone(ET)
                    print(f"User proposed time in ET: {user_time_et}")
                    # Propose this slot if available
                    available_slots = [{'slot': user_time_et, 'duration': preferences.get('duration', 60)}]
                except Exception as e:
                    print(f"Could not parse or convert user time: {e}")
                    # Fallback to normal slot search
                    available_slots = find_available_slots(calendar_service, owner_email, preferences)
            else:
                available_slots = find_available_slots(calendar_service, owner_email, preferences)
            print(f"Available slots: {available_slots}")

            if not available_slots:
                # Fallback: offer a default slot tomorrow at 10am
                print("No available slots found, offering default slot.")
                tomorrow = datetime.now(ET) + timedelta(days=1)
                default_slot = ET.localize(datetime.combine(tomorrow.date(), time(10, 0)))
                available_slots = [{"slot": default_slot, "duration": 60}]

            slots_text = ""
            hidden_data_for_body = ""
            for i, slot_data in enumerate(available_slots):
                slot_et = slot_data['slot']
                # If user proposed a time and a zone, show both ET and user's zone
                if user_time_et and preferences.get('time_zone'):
                    try:
                        user_tz = pytz.timezone(str(preferences['time_zone']))
                        slot_user_tz = slot_et.astimezone(user_tz)
                        slots_text += f"- {slot_user_tz.strftime('%A, %B %d at %I:%M %p')} {preferences['time_zone']} / {slot_et.strftime('%I:%M %p ET')}\n"
                    except Exception:
                        slots_text += f"- {slot_et.strftime('%A, %B %d at %I:%M %p ET')}\n"
                else:
                    slots_text += f"- {slot_et.strftime('%A, %B %d at %I:%M %p ET')}\n"
                hidden_info = json.dumps({'start': slot_et.isoformat(), 'duration': slot_data['duration']})
                hidden_data_for_body += f"<!-- data: {hidden_info} -->\n"
                hidden_data_for_body += f'<span style="display:none;">SLOT_DATA:{hidden_info}</span>\n'

            all_emails_str = original_to + "," + original_cc + "," + original_from_header
            all_emails = list(set(re.findall(r'[\w\.+-]+@[\w\.-]+\.[\w\.-]+', all_emails_str)))
            participants = [email for email in all_emails if email not in [agent_email, owner_email]]
            to_field = ", ".join(participants)
            cc_field = owner_email

            if not participants:
                print("No valid participants found for To field. Using original sender as recipient.")
                # Try to extract sender from original_from_header
                sender_match = re.search(r'[\w\.+-]+@[\w\.-]+\.[\w\.-]+', original_from_header)
                if sender_match:
                    to_field = sender_match.group(0)
                else:
                    print("Could not extract sender email. Aborting send.")
                    return "No valid recipient found.", 500

            print(f"To field: {to_field}, CC field: {cc_field}")

            try:
                genai.configure(api_key=gemini_api_key)
                model = genai.GenerativeModel('gemini-2.5-flash')
                # --- In all agent email composition (INITIAL_REQUEST, OTHER, etc):
                # 1. Remove greeting_template, greeting_name, and Gemini greeting prompt logic.
                # 2. Only ask Gemini for the main body (slot list, instructions, etc.).
                # 3. Always prepend 'Hi<br><br>' to the email body in the HTML.
                prompt = f"""
                You are a helpful AI assistant for {owner_name}.
                Write a brief, friendly, and natural-sounding email to propose meeting times. Do NOT include a greeting or recipient name. The available time slots are:
                {slots_text}
                Your response should be conversational and not robotic. Do NOT include a subject line or greeting. End by saying something like, 'Let me know if any of these work for you!'
                """
                email_response = model.generate_content(prompt)
                email_body_text = email_response.text

                # --- PATCH: Consistent professional signature and simplified greeting for all agent emails ---
                # Replace all email body composition (INITIAL_REQUEST, OTHER, etc) with:
                # greeting_line = 'Hi'<br><br> + email_body_text
                # signature_html = ... (the new professional signature)
                # html_body = f"<html><body><p>{greeting_line}{email_body_text.replace(os.linesep, '<br>')}</p>{hidden_data_for_body}{signature_html}</body></html>"
                signature_html = f"""
                <div style='margin-top:32px; margin-bottom:8px; border-top:1px solid #e0e0e0;'></div>
                <div style='color:#222; font-size:13px; font-family:sans-serif; margin-top:8px;'>
                  <strong>Anntao's AI Assistant</strong><br>
                  <span style='color:#888;'>on behalf of {owner_name}</span>
                </div>
                """
                html_body = f"""
                <html><body>
                <p>Hi<br><br>{email_body_text.replace(os.linesep, '<br>')}</p>
                {hidden_data_for_body}
                {signature_html}
                </body></html>
                """

                clean_subject = f"Re: {subject.replace('Re: ', '')}"
                email_message = create_threaded_email(agent_email, to_field, cc_field, clean_subject, html_body, in_reply_to=message_id_header, references=new_references)
                send_email(gmail_service, 'me', email_message, thread_id=thread_id)
                print(f"Sent time slot suggestions to {to_field}")
                doc_ref.set({'timestamp': firestore.SERVER_TIMESTAMP})
                gmail_service.users().messages().modify(userId='me', id=msg_id, body={'removeLabelIds': ['UNREAD']}).execute()
                print(f"Marked message {msg_id} as read and set historyId {history_id}")
            except Exception as e:
                print(f"Exception during slot suggestion or email send: {e}")
                return "Error sending email.", 500

    except Exception as e:
        import traceback
        print(f"An error occurred during processing: {e}")
        traceback.print_exc()
        return "An error occurred.", 500

    return "Processing complete.", 200

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint for Cloud Run."""
    return 'OK', 200

@app.route('/ping', methods=['POST'])
def ping_refresh_gmail_watch():
    """Ping endpoint to refresh Gmail watch, called by Cloud Scheduler."""
    try:
        print("PING: Starting ping endpoint...")
        
        # Step 1: Test basic functionality
        print("PING: Step 1 - Basic endpoint test")
        
        # Step 2: Test project ID determination
        try:
            _, project_id = google.auth.default()
            print(f"PING: Step 2 - Project ID determined: {project_id}")
        except Exception as e:
            print(f"PING ERROR: Failed to get project ID: {e}")
            return f"Project ID error: {str(e)}", 500
        
        # Step 3: Test Firestore client
        try:
            db = firestore.Client(project=project_id)
            print("PING: Step 3 - Firestore client created successfully")
        except Exception as e:
            print(f"PING ERROR: Failed to create Firestore client: {e}")
            return f"Firestore error: {str(e)}", 500
        
        # Step 4: Test authentication
        try:
            print("PING: Step 4 - Attempting to authenticate with secrets...")
            creds = authenticate_with_secrets(project_id)
            if not creds:
                print("PING ERROR: Authentication failed")
                return "Authentication failed.", 500
            print("PING: Step 4 - Authentication successful")
        except Exception as e:
            print(f"PING ERROR: Authentication exception: {e}")
            return f"Authentication exception: {str(e)}", 500
        
        # Step 5: Test Gmail service
        try:
            print("PING: Step 5 - Building Gmail service...")
            gmail_service = build('gmail', 'v1', credentials=creds)
            print("PING: Step 5 - Gmail service built successfully")
        except Exception as e:
            print(f"PING ERROR: Failed to build Gmail service: {e}")
            return f"Gmail service error: {str(e)}", 500
        
        # Step 6: Test watch refresh
        try:
            print("PING: Step 6 - Calling maybe_refresh_gmail_watch...")
            maybe_refresh_gmail_watch(gmail_service, db, project_id)
            print("PING: Step 6 - maybe_refresh_gmail_watch completed successfully")
        except Exception as e:
            print(f"PING ERROR: Watch refresh failed: {e}")
            return f"Watch refresh error: {str(e)}", 500
        
        print("PING: All steps completed successfully!")
        return "Ping: Gmail watch checked/refreshed.", 200
        
    except Exception as e:
        print(f"PING ERROR: Unexpected exception: {e}")
        import traceback
        traceback.print_exc()
        return f"Unexpected error: {str(e)}", 500

# This block is essential for the server to start.
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    app.run(debug=True, host='0.0.0.0', port=port)
