import json
import requests
import subprocess
import sys
import os
from datetime import datetime
from dotenv import load_dotenv

# Dynamic path detection for cross-platform support
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(SCRIPT_DIR, "../../"))

CONFIG_FILE = os.path.join(PROJECT_ROOT, "Config", "zoho_oauth.json")
QUALYS_MASTER_CSV = os.path.join(PROJECT_ROOT, "Qualys", "Qualys_Master_DB", "Qualys_Master_DB.csv")

# Load customer-specific settings from .env
load_dotenv(os.path.join(PROJECT_ROOT, "Config", ".env"))

SDP_DOMAIN = os.getenv("SDP_DOMAIN", "https://sdpondemand.manageengine.in")
SDP_PORTAL = os.getenv("SDP_PORTAL", "itdesk")

QUALYS_TO_SDP_SCRIPT = os.path.join(SCRIPT_DIR, "Qualys_to_sdp.py")
STATE_FILE = os.path.join(PROJECT_ROOT, "Qualys", "State", "sdp_qualys_state.json")
FIXED_TICKETS_CSV = os.path.join(PROJECT_ROOT, "Qualys", "State", "to_be_closed.csv")
ROUTING_RULES_FILE = os.path.join(PROJECT_ROOT, "Config", "routing_rules.json")

def get_access_token():
    with open(CONFIG_FILE, "r") as f:
        cfg = json.load(f)

    data = {
        "grant_type": "refresh_token",
        "refresh_token": cfg["refresh_token"],
        "client_id": cfg["client_id"],
        "client_secret": cfg["client_secret"]
    }

    response = requests.post(cfg["token_url"], data=data)
    response.raise_for_status()

    return response.json()["access_token"]


def run_ticket_script(token, dry_run=False):
    command = [
        sys.executable,
        QUALYS_TO_SDP_SCRIPT,
        "--csv", QUALYS_MASTER_CSV,
        "--domain", SDP_DOMAIN,
        "--portal", SDP_PORTAL,
        "--token", token,
        "--statefile", STATE_FILE,
        "--close-fixed", FIXED_TICKETS_CSV,
        "--routing-rules", ROUTING_RULES_FILE,
        "--no-urgency"
    ]

    if dry_run:
        command.append("--dry-run")

    subprocess.run(command, check=True)



if __name__ == "__main__":
    print("=== Starting Qualys -> ME Workflow ===")

    dry_run = "--dry-run" in sys.argv

    token = get_access_token()
    print("New token generated")

    run_ticket_script(token, dry_run=dry_run)

    print("Workflow completed successfully")

