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
from google.cloud import firestore
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import time as sleep_timer

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

def authenticate_with_secrets(project_id):
    """Authenticates with Google APIs using credentials from Secret Manager."""
    creds = None
    if not project_id:
        print("ERROR: GCP_PROJECT could not be determined.")
        return None

    token_json_str = get_secret(project_id, "agent-token-json")
    
    if not token_json_str:
        print("ERROR: Could not retrieve token from Secret Manager.")
        return None

    try:
        creds_info = json.loads(token_json_str)
        creds = Credentials.from_authorized_user_info(creds_info, SCOPES)
    except Exception as e:
        print(f"ERROR: Could not load credentials from secret data. Error: {e}")
        return None

    if creds and creds.expired and creds.refresh_token:
        try:
            print("Token expired, attempting to refresh...")
            creds.refresh(Request())
            print("Token refreshed successfully for this session.")
        except Exception as e:
            print(f"ERROR: Could not refresh token. A new token may need to be generated manually. Error: {e}")
            return None
            
    return creds

def get_email_intent_with_ai(email_thread_text, current_date_et, api_key):
    """Uses Gemini to parse the user's intent from the full email thread."""
    if not api_key:
        print("WARN: Gemini API key is not configured. Using fallback.")
        return {'duration': 60, 'day_preference': None, 'time_of_day': None, 'start_date': None}
        
    try:
        genai.configure(api_key=api_key)
        model = genai.GenerativeModel('gemini-1.5-flash-latest')
        prompt = f"""
        Analyze the following email thread to determine scheduling preferences. The current date is {current_date_et.strftime('%Y-%m-%d')}.
        Your goal is to be a helpful assistant.

        1.  **Duration**: Find the meeting duration in minutes (e.g., 30 or 60). Default to 60.
        2.  **Day Preference**: Identify a specific day of the week if mentioned (e.g., "Monday", "Friday").
        3.  **Time of Day**: Identify a time preference ("morning", "afternoon").
        4.  **Start Date**: If the user mentions a relative date (e.g., "next week", "end of the week", "tomorrow"), calculate the target start date in 'YYYY-MM-DD' format. If no relative date is mentioned, this should be null.

        Return a JSON object with keys: "duration", "day_preference", "time_of_day", and "start_date".
        If a value isn't specified, use null.

        Email Thread: "{email_thread_text}"

        JSON:
        """
        response = model.generate_content(prompt)
        json_str = response.text.strip().replace('```json', '').replace('```', '').strip()
        return json.loads(json_str)
    except Exception as e:
        print(f"AI parsing failed: {e}. Using default values.")
        return {'duration': 60, 'day_preference': None, 'time_of_day': None, 'start_date': None}

def find_available_slots(service, calendar_id, preferences):
    """Finds available slots based on AI-parsed preferences, skipping weekends."""
    duration_minutes = preferences.get('duration', 60)
    day_preference = preferences.get('day_preference')
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
    message['from'] = sender
    message['cc'] = cc
    message['subject'] = subject
    message['In-Reply-To'] = in_reply_to
    message['References'] = references
    message['X-Agent-Processed'] = 'true'
    
    message.attach(MIMEText(html_body, 'html'))
    return {'raw': base64.urlsafe_b64encode(message.as_bytes()).decode()}

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
        'reminders': {'useDefault': True},
    }
    created_event = service.events().insert(calendarId=calendar_id, body=event, sendNotifications=True).execute()
    print(f'Event created: {created_event.get("htmlLink")}')

def get_full_email_text(payload):
    """Recursively extracts all plain text from an email payload."""
    body = ""
    if payload.get('body') and payload['body'].get('data'):
        data = payload['body']['data']
        body += base64.urlsafe_b64decode(data).decode('utf-8', errors='ignore')
    
    if 'parts' in payload:
        for part in payload['parts']:
            if part['mimeType'] == 'text/plain':
                if part.get('body') and part['body'].get('data'):
                    data = part['body']['data']
                    body += base64.urlsafe_b64decode(data).decode('utf-8', errors='ignore')
            elif 'parts' in part:
                 body += get_full_email_text(part)
    return body

@app.route('/', methods=['POST'])
def process_email_request():
    """Entry point for all requests, triggered by Pub/Sub."""
    
    envelope = request.get_json()
    if not envelope or 'message' not in envelope:
        print('Invalid Pub/Sub message format. This may be a health check.')
        return 'OK', 200
    
    # --- FIX: Moved environment discovery and client initialization inside the request handler ---
    try:
        _, project_id = google.auth.default()
        db = firestore.Client(project=project_id)
    except google.auth.exceptions.DefaultCredentialsError:
        print("ERROR: Could not automatically determine project ID.")
        return "Internal Server Error", 500

    gemini_api_key = os.environ.get("GEMINI_API_KEY")
    
    # --- FIX: Use Firestore for robust deduplication ---
    try:
        data = json.loads(base64.b64decode(envelope['message']['data']).decode('utf-8'))
        history_id = str(data['historyId']) # Ensure historyId is a string
        doc_ref = db.collection('processed_history').document(history_id)
        
        @firestore.transactional
        def check_and_set_history(transaction, doc_ref):
            snapshot = doc_ref.get(transaction=transaction)
            if snapshot.exists:
                return True # Indicates duplicate
            else:
                transaction.set(doc_ref, {'timestamp': firestore.SERVER_TIMESTAMP})
                return False # Indicates not a duplicate

        transaction = db.transaction()
        is_duplicate = check_and_set_history(transaction, doc_ref)

        if is_duplicate:
            print(f"Duplicate historyId detected: {history_id}. Ignoring.")
            return "Duplicate message", 200

    except Exception as e:
        print(f"Firestore deduplication check failed: {e}")
        return "Internal Server Error", 500
    
    sleep_timer.sleep(5)
    
    agent_email = 'anntaoai@gmail.com'
    owner_email = 'anntaod@gmail.com'
    owner_name = 'Anntao'

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
        
        # --- FIX: Mark as read immediately to avoid race conditions ---
        gmail_service.users().messages().modify(userId='me', id=msg_id, body={'removeLabelIds': ['UNREAD']}).execute()
        
        message = gmail_service.users().messages().get(userId='me', id=msg_id, format='full').execute()
        
        headers = message['payload']['headers']
        is_agent_sent = any(h['name'] == 'X-Agent-Processed' and h['value'] == 'true' for h in headers)
        if is_agent_sent:
            print(f"Ignoring agent's own message: {msg_id}")
            return "Agent message ignored.", 200

        subject = next((h['value'] for h in headers if h['name'].lower() == 'subject'), 'No Subject')
        full_email_text = get_full_email_text(message['payload'])
        
        message_id_header = next((h['value'] for h in headers if h['name'].lower() == 'message-id'), None)
        references_header = next((h['value'] for h in headers if h['name'].lower() == 'references'), '')
        new_references = f"{references_header} {message_id_header}".strip()

        original_to = next((h['value'] for h in headers if h['name'].lower() == 'to'), '')
        original_cc = next((h['value'] for h in headers if h['name'].lower() == 'cc'), '')
        original_from_header = next((h['value'] for h in headers if h['name'].lower() == 'from'), '')
        
        if owner_email not in (original_to + original_cc + original_from_header):
             print(f"Owner ({owner_email}) not in participants. Ignoring email.")
             return "Owner not in thread, request ignored.", 200

        hidden_data_matches = re.findall(r'<!-- data: (.*?) -->', full_email_text)

        # --- FIX: Improved logic to handle replies ---
        is_reply_to_agent = "AI assistant" in full_email_text and hidden_data_matches and owner_email not in original_from_header

        if is_reply_to_agent:
            print("Detected reply to agent. Attempting to schedule event.")
            possible_slots_text = ""
            for i, hidden_info_str in enumerate(hidden_data_matches):
                slot_data = json.loads(hidden_info_str)
                start_time_et = ET.localize(datetime.fromisoformat(slot_data['start']))
                possible_slots_text += f"Option {i+1}: {start_time_et.strftime('%A, %B %d at %I:%M %p ET')} for {slot_data['duration']} minutes.\n"
            
            genai.configure(api_key=gemini_api_key)
            model = genai.GenerativeModel('gemini-1.5-flash-latest')
            prompt = f"""
            Read the user's reply to determine which option they chose for the meeting.
            The options offered were:
            {possible_slots_text}
            The user's reply is: "{full_email_text}"
            Respond with a JSON object containing one key: "chosen_option_number".
            The value should be the integer of the chosen option (e.g., 1, 2, or 3).
            If the user did not clearly choose an option, respond with null.
            JSON:
            """
            response = model.generate_content(prompt)
            json_str = response.text.strip().replace('```json', '').replace('```', '').strip()
            choice_data = json.loads(json_str)
            chosen_option = choice_data.get('chosen_option_number')

            if chosen_option and len(hidden_data_matches) >= chosen_option:
                event_data = json.loads(hidden_data_matches[chosen_option - 1])
                start_time_et = ET.localize(datetime.fromisoformat(event_data['start']))
                duration = event_data['duration']
                
                # --- FIX: Correct participant parsing ---
                all_emails_str = original_to + "," + original_cc + "," + original_from_header
                attendees = list(set(re.findall(r'[\w\.\+-]+@[\w\.-]+\.[\w\.-]+', all_emails_str)))
                if owner_email not in attendees:
                    attendees.append(owner_email)
                attendees = [email for email in attendees if email != agent_email]

                create_calendar_event(calendar_service, owner_email, f"Meeting: {subject.replace('Re: ', '')}", start_time_et, duration, attendees)
                print(f"Event scheduled with {', '.join(attendees)}")
        
        else:
            print("Detected initial request. Finding slots.")
            preferences = get_email_intent_with_ai(full_email_text, datetime.now(ET), gemini_api_key)
            available_slots = find_available_slots(calendar_service, owner_email, preferences)
            
            if available_slots:
                slots_text = ""
                hidden_data_for_body = ""
                for i, slot_data in enumerate(available_slots):
                    slot_et = slot_data['slot']
                    slots_text += f"- {slot_et.strftime('%A, %B %d at %I:%M %p ET')}\n"
                    hidden_info = json.dumps({'start': slot_et.isoformat(), 'duration': slot_data['duration']})
                    hidden_data_for_body += f"<!-- data: {hidden_info} -->\n"
                
                sender_name_match = re.search(r'"?([^<"]+)"?\s*<', original_from_header)
                recipient_name = sender_name_match.group(1).strip() if sender_name_match else "there"

                genai.configure(api_key=gemini_api_key)
                model = genai.GenerativeModel('gemini-1.5-flash-latest')
                prompt = f"""
                You are a helpful AI assistant for {owner_name}.
                Write a brief, friendly, and natural-sounding email to {recipient_name} to propose meeting times.
                
                The available time slots are:
                {slots_text}

                Your response should be conversational (e.g., "Hi {recipient_name}, I'm helping {owner_name} coordinate a meeting... Here are a few times that work:").
                Do NOT include a subject line in your response.
                End by saying something like, "Let me know if any of these work for you!"
                """
                email_response = model.generate_content(prompt)
                email_body_text = email_response.text

                html_body = f"""
                <html><body>
                <p>{email_body_text.replace(os.linesep, '<br>')}</p>
                {hidden_data_for_body}
                </body></html>
                """

                clean_subject = f"Re: {subject.replace('Re: ', '')}"
                
                all_emails_str = original_to + "," + original_cc + "," + original_from_header
                all_emails = list(set(re.findall(r'[\w\.\+-]+@[\w\.-]+\.[\w\.-]+', all_emails_str)))
                
                participants = [email for email in all_emails if email not in [agent_email, owner_email]]
                
                to_field = ", ".join(participants)
                cc_field = owner_email
                
                email_message = create_threaded_email(agent_email, to_field, cc_field, clean_subject, html_body, in_reply_to=message_id_header, references=new_references)
                send_email(gmail_service, 'me', email_message)
                print(f"Sent time slot suggestions to {to_field}")
            else:
                 print("No available slots found matching the criteria.")

    except Exception as e:
        print(f"An error occurred during processing: {e}")
        return "An error occurred.", 500

    return "Processing complete.", 200

# This block is essential for the server to start.
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    app.run(debug=True, host='0.0.0.0', port=port)
