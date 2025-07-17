import os
import base64
import re
import json
from datetime import datetime, timedelta
import pytz
import google.generativeai as genai
from flask import Flask, request
from google.auth.transport.requests import Request
from googleapiclient.discovery import build
from google.cloud import secretmanager
from google.cloud import firestore
from google.oauth2 import service_account

app = Flask(__name__)

ET = pytz.timezone('US/Eastern')

# Load Firestore
db = firestore.Client()

# Load secrets from Secret Manager
def get_secret(secret_id):
    client = secretmanager.SecretManagerServiceClient()
    project_id = os.environ["GCP_PROJECT"]
    name = f"projects/{project_id}/secrets/{secret_id}/versions/latest"
    response = client.access_secret_version(request={"name": name})
    return response.payload.data.decode("UTF-8")

gemini_api_key = get_secret("GEMINI_API_KEY")
service_account_info = json.loads(get_secret("SERVICE_ACCOUNT_JSON"))

credentials = service_account.Credentials.from_service_account_info(service_account_info, scopes=['https://www.googleapis.com/auth/calendar'])
calendar_service = build('calendar', 'v3', credentials=credentials)

def create_calendar_event(service, owner_email, summary, start_time, duration, attendees):
    end_time = start_time + timedelta(minutes=duration)
    event = {
        'summary': summary,
        'start': {'dateTime': start_time.isoformat(), 'timeZone': 'US/Eastern'},
        'end': {'dateTime': end_time.isoformat(), 'timeZone': 'US/Eastern'},
        'attendees': [{'email': email} for email in attendees],
    }
    return service.events().insert(calendarId=owner_email, body=event, sendUpdates='all').execute()

@app.route("/email-hook", methods=["POST"])
def handle_email():
    data = request.get_json()

    email_data = data["email"]
    email_id = email_data["id"]
    full_email_text = email_data["body"]
    subject = email_data["subject"]
    original_to = email_data["to"]
    original_cc = email_data.get("cc", "")
    original_from_header = email_data["from"]
    agent_email = email_data["agent"]
    owner_email = email_data["owner"]

    hidden_data_matches = re.findall(r'<!-- data: (.*?) -->', full_email_text)

    if hidden_data_matches and owner_email not in original_from_header:
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
        Respond with a JSON object containing one key: \"chosen_option_number\".
        The value should be the integer of the chosen option (e.g., 1, 2, or 3).
        If the user did not clearly choose an option, respond with null.
        JSON:
        """
        response = model.generate_content(prompt)
        json_str = response.text.strip().replace('\njson', '').replace('\n', '').strip()
        print(f"Gemini raw response: {json_str}")

        try:
            choice_data = json.loads(json_str)
            chosen_option = int(choice_data.get('chosen_option_number'))
        except (ValueError, TypeError, json.JSONDecodeError) as e:
            print(f"Error parsing Gemini response: {e}")
            chosen_option = None

        if chosen_option and 1 <= chosen_option <= len(hidden_data_matches):
            event_data = json.loads(hidden_data_matches[chosen_option - 1])
            start_time_et = ET.localize(datetime.fromisoformat(event_data['start']))
            duration = event_data['duration']

            all_emails_str = original_to + "," + original_cc + "," + original_from_header
            attendees = list(set(re.findall(r'[\w\.\+-]+@[\w\.-]+\.[\w\.-]+', all_emails_str)))
            if owner_email not in attendees:
                attendees.append(owner_email)
            attendees = [email for email in attendees if email != agent_email]

            create_calendar_event(
                calendar_service,
                owner_email,
                f"Meeting: {subject.replace('Re: ', '')}",
                start_time_et,
                duration,
                attendees
            )
            print(f"Event scheduled with {', '.join(attendees)}")
            return "Event created.", 200
        else:
            print("Could not determine user's choice from reply. Will re-suggest.")
            # Fallthrough to initial request logic is intended here if choice is unclear

    return "No action taken.", 200

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=int(os.environ.get('PORT', 8080)))
