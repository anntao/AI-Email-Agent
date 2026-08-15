#!/usr/bin/env python3
"""Generate the OAuth token that the agent stores in Secret Manager.

Run this from the agent's Google account, not the owner's.

The scopes here are narrower than the original https://mail.google.com/ grant,
so an existing token will NOT satisfy them — you have to re-run this once after
upgrading and upload the result as a new version of the agent-token-json secret.
"""

import argparse
import json
import os
import subprocess
import sys

from google_auth_oauthlib.flow import InstalledAppFlow

from agent.config import SCOPES, TOKEN_SECRET_ID

CLIENT_SECRETS = "credentials.json"


def generate(client_secrets: str) -> dict:
    if not os.path.exists(client_secrets):
        sys.exit(
            f"ERROR: {client_secrets} not found.\n"
            "Download the OAuth 2.0 Desktop client config from Google Cloud Console "
            f"(APIs & Services > Credentials) and save it as {client_secrets}."
        )

    flow = InstalledAppFlow.from_client_secrets_file(client_secrets, SCOPES)
    # prompt='consent' forces a refresh token even if this account has authorised
    # the app before. Without it, a re-run can return a token that cannot refresh.
    creds = flow.run_local_server(port=0, prompt="consent", access_type="offline")

    if not creds.refresh_token:
        sys.exit("ERROR: Google did not return a refresh token. Revoke the app's access "
                 "at https://myaccount.google.com/permissions and run this again.")

    return {
        "token": creds.token,
        "refresh_token": creds.refresh_token,
        "token_uri": creds.token_uri,
        "client_id": creds.client_id,
        "client_secret": creds.client_secret,
        "scopes": list(creds.scopes or SCOPES),
    }


def upload(project_id: str, payload: dict) -> None:
    process = subprocess.run(
        ["gcloud", "secrets", "versions", "add", TOKEN_SECRET_ID,
         f"--project={project_id}", "--data-file=-"],
        input=json.dumps(payload).encode(),
        capture_output=True,
    )
    if process.returncode != 0:
        sys.exit(f"gcloud failed: {process.stderr.decode().strip()}")
    print(f"Uploaded a new version of {TOKEN_SECRET_ID} to project {project_id}.")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--client-secrets", default=CLIENT_SECRETS)
    parser.add_argument("--project", help="Upload straight to this project's Secret Manager")
    parser.add_argument("--print", action="store_true", dest="show",
                        help="Print the token JSON to stdout (contains a refresh token)")
    args = parser.parse_args()

    print("Requesting scopes:\n  " + "\n  ".join(SCOPES) + "\n")
    payload = generate(args.client_secrets)

    if args.project:
        upload(args.project, payload)
    elif args.show:
        print(json.dumps(payload, indent=2))
    else:
        with open("token.json", "w") as handle:
            json.dump(payload, handle, indent=2)
        print("Wrote token.json (gitignored).")
        print(f"Upload it with:\n  gcloud secrets versions add {TOKEN_SECRET_ID} "
              "--data-file=token.json")

    print("\nAfter uploading, redeploy so the service picks up the new token.")


if __name__ == "__main__":
    main()
