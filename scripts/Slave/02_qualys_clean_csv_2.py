import os
import glob
import logging
from datetime import datetime

# ================= CONFIG =================
# Dynamic path detection for portability
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
INPUT_DIR = os.path.join(BASE_DIR, "Qualys", "Qualys_Download_Vuln_Report")
OUTPUT_DIR = os.path.join(BASE_DIR, "Qualys", "Qualys_Cleaned_Report")
LOG_DIR = os.path.join(BASE_DIR, "logs")

# Ensure directories exist
os.makedirs(OUTPUT_DIR, exist_ok=True)
os.makedirs(LOG_DIR, exist_ok=True)

# Setup logging
timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
log_file = os.path.join(LOG_DIR, f"clean_qualys_{timestamp}.log")
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler(log_file),
        logging.StreamHandler()
    ]
)

def clean_csv():
    logging.info("==============================================")
    logging.info("[START] Qualys CSV Cleanup (Python Version)")
    logging.info(f"[TIME] {datetime.now()}")
    logging.info("==============================================")

    # 1. Find latest Qualys CSV
    search_pattern = os.path.join(INPUT_DIR, "Cloud_Agent_Vuln_Report_*.csv")
    csv_files = glob.glob(search_pattern)
    
    if not csv_files:
        logging.error(f"No Qualys CSV file found in {INPUT_DIR}")
        return

    # Sort by modification time to get the latest
    latest_file = max(csv_files, key=os.path.getmtime)
    logging.info(f"[INFO] Latest Qualys CSV detected: {latest_file}")

    # 2. Delete old cleaned files
    output_file = os.path.join(OUTPUT_DIR, "ME_Qualys_Vuln_Report.csv")
    if os.path.exists(output_file):
        os.remove(output_file)
        logging.info("[INFO] Removed old cleaned report")

    # 3. Process the file
    logging.info("[STEP] Finding header and cleaning data...")
    header_found = False
    
    try:
        with open(latest_file, 'r', encoding='utf-8', errors='ignore') as f_in, \
             open(output_file, 'w', encoding='utf-8', newline='') as f_out:
            
            for line in f_in:
                if not header_found:
                    # Look for Qualys header keywords
                    if "TITLE" in line.upper() and "QID" in line.upper() and "SEVERITY" in line.upper():
                        header_found = True
                        f_out.write(line)
                        logging.info("[INFO] Header row detected and processing started")
                else:
                    f_out.write(line)

        if not header_found:
            logging.error("[ERROR] Could not locate Qualys header row (IP, TITLE, QID, etc.)")
            return

        logging.info(f"[SUCCESS] CSV cleaned successfully. Saved to: {output_file}")

    except Exception as e:
        logging.error(f"[ERROR] An error occurred during file processing: {str(e)}")

    logging.info("==============================================")
    logging.info("[DONE] Cleaning completed")
    logging.info(f"[END TIME] {datetime.now()}")
    logging.info("==============================================")

if __name__ == "__main__":
    clean_csv()
