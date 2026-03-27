import os
import requests
import time
import logging
import xml.etree.ElementTree as ET
from datetime import datetime
from dotenv import load_dotenv

# ================= CONFIG =================
# Dynamic path detection for portability
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
CONFIG_DIR = os.path.join(BASE_DIR, "Config")
OUTPUT_DIR = os.path.join(BASE_DIR, "Qualys", "Qualys_Download_Vuln_Report")
LOG_DIR = os.path.join(BASE_DIR, "logs")

# Load environment variables
load_dotenv(os.path.join(CONFIG_DIR, ".env"))

BASE_URL = os.getenv("QUALYS_BASE_URL", "https://qualysapi.qg1.apps.qualys.in")
USER = os.getenv("QUALYS_USER")
PASS = os.getenv("QUALYS_PASS")

TEMPLATE_ID = os.getenv("QUALYS_TEMPLATE_ID", "4922455")
REPORT_TITLE = os.getenv("QUALYS_REPORT_TITLE", "Cloud_Agent_Vuln_Report")
TAG_ID = os.getenv("QUALYS_TAG_ID", "28214141")

TIMESTAMP = datetime.now().strftime("%Y%m%d_%H%M%S")
log_file = os.path.join(LOG_DIR, f"download_qualys_{TIMESTAMP}.log")

# Setup logging
os.makedirs(OUTPUT_DIR, exist_ok=True)
os.makedirs(LOG_DIR, exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[logging.FileHandler(log_file), logging.StreamHandler()]
)

def run_download():
    logging.info("=================================================")
    logging.info("[START] Qualys Full Cleanup + Download Automation")
    logging.info(f"[TIME] {datetime.now()}")
    logging.info("=================================================")

    if not USER or not PASS:
        logging.error("Credentials missing in .env file")
        return

    # 0. Local Cleanup (Keep only latest)
    logging.info("[STEP 0] Cleaning local output directory...")
    if os.path.exists(OUTPUT_DIR):
        for f in os.listdir(OUTPUT_DIR):
            if f.startswith(REPORT_TITLE) and f.endswith(".csv"):
                file_path = os.path.join(OUTPUT_DIR, f)
                try:
                    os.remove(file_path)
                    logging.info(f"[DELETE] Local file: {f}")
                except Exception as e:
                    logging.error(f"Error deleting local file {f}: {e}")

    # 1. List and delete existing reports
    logging.info("[STEP 1] Listing existing reports...")
    try:
        response = requests.get(
            f"{BASE_URL}/api/3.0/fo/report/?action=list",
            auth=(USER, PASS),
            headers={"X-Requested-With": "Python"}
        )
        response.raise_for_status()
        
        # Parse XML for Report IDs
        root = ET.fromstring(response.content)
        report_ids = [rid.text for rid in root.findall(".//ID")]

        if not report_ids:
            logging.info("[INFO] No existing reports found")
        else:
            logging.info(f"[INFO] {len(report_ids)} reports found. Deleting...")
            for rid in report_ids:
                logging.info(f"[DELETE] Report ID: {rid}")
                requests.post(
                    f"{BASE_URL}/api/3.0/fo/report/",
                    auth=(USER, PASS),
                    data={"action": "delete", "id": rid},
                    headers={"X-Requested-With": "Python"}
                )
                time.sleep(1)
    except Exception as e:
        logging.error(f"Error listing/deleting reports: {e}")

    # 2. Launch new report
    logging.info("[STEP 3] Launching new report...")
    try:
        data = {
            "action": "launch",
            "template_id": TEMPLATE_ID,
            "report_title": REPORT_TITLE,
            "output_format": "csv",
            "use_tags": "1",
            "tag_set_by": "id",
            "tag_set_include": TAG_ID
        }
        response = requests.post(
            f"{BASE_URL}/api/3.0/fo/report/",
            auth=(USER, PASS),
            data=data,
            headers={"X-Requested-With": "Python"}
        )
        response.raise_for_status()
        
        root = ET.fromstring(response.content)
        report_id = None
        
        # 1. Direct ID node check
        id_node = root.find(".//ID")
        if id_node is not None and id_node.text:
            report_id = str(id_node.text).strip()
        
        # 2. Sequential KEY/VALUE check (more robust for Qualys)
        if not report_id:
            # We iterate through everything to find the VALUE that follows the KEY 'ID'
            found_id_key = False
            for elem in root.iter():
                if elem.tag == "KEY" and elem.text == "ID":
                    found_id_key = True
                elif elem.tag == "VALUE" and found_id_key:
                    if elem.text is not None:
                        txt = str(elem.text).strip()
                        if txt.isdigit():
                            report_id = txt
                            break
                    # If we find a VALUE but it's not the ID, we should probably stop looking for ID
                    found_id_key = False
        
        # 3. Fallback: just look for the first numerical VALUE
        if not report_id:
            for value in root.findall(".//VALUE"):
                if value is not None and value.text:
                    txt = str(value.text).strip()
                    if txt.isdigit():
                        report_id = txt
                        break

        if not report_id:
            logging.error(f"Report launch failed to extract ID. Response: {response.text}")
            return

        logging.info(f"[INFO] Report launched | ID: {report_id}")

        # 3. Wait for completion
        logging.info("[STEP 4] Waiting for report completion...")
        start_time = time.time()
        max_wait = 1800
        
        while True:
            status_resp = requests.get(
                f"{BASE_URL}/api/3.0/fo/report/?action=list&id={report_id}",
                auth=(USER, PASS),
                headers={"X-Requested-With": "Python"}
            )
            status_root = ET.fromstring(status_resp.content)
            
            # Find status in XML
            state = "Unknown"
            state_node = status_root.find(".//STATE")
            if state_node is not None:
                state = state_node.text
            
            elapsed = int(time.time() - start_time)
            logging.info(f"Status: {state} | Elapsed: {elapsed}s")

            if state == "Finished":
                break
            
            if elapsed >= max_wait:
                logging.error("[ERROR] Report stuck. Deleting.")
                requests.post(
                    f"{BASE_URL}/api/3.0/fo/report/",
                    auth=(USER, PASS),
                    data={"action": "delete", "id": report_id},
                    headers={"X-Requested-With": "Python"}
                )
                return
            
            time.sleep(30)

        # 4. Download report
        logging.info("[STEP 5] Downloading report...")
        output_file = os.path.join(OUTPUT_DIR, f"Cloud_Agent_Vuln_Report_{TIMESTAMP}.csv")
        fetch_resp = requests.get(
            f"{BASE_URL}/api/3.0/fo/report/?action=fetch&id={report_id}",
            auth=(USER, PASS),
            stream=True,
            headers={"X-Requested-With": "Python"}
        )
        
        with open(output_file, 'wb') as f:
            for chunk in fetch_resp.iter_content(chunk_size=8192):
                f.write(chunk)

        if os.path.getsize(output_file) > 100:
            logging.info(f"[SUCCESS] File saved: {output_file}")
        else:
            logging.error("[ERROR] Download failed or file too small")
            return

        # 5. Final cleanup
        logging.info("[STEP 6] Final cleanup (delete report)...")
        requests.post(
            f"{BASE_URL}/api/3.0/fo/report/",
            auth=(USER, PASS),
            data={"action": "delete", "id": report_id},
            headers={"X-Requested-With": "Python"}
        )

    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")

    logging.info("=================================================")
    logging.info("[COMPLETE]")
    logging.info("=================================================")

if __name__ == "__main__":
    run_download()
