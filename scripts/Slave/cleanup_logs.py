import os
import shutil
import glob
from datetime import datetime
import logging
from typing import List

# ================= CONFIG =================
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
SLAVE_DIR = os.path.join(BASE_DIR, "scripts", "Slave")
LOG_DIR = os.path.join(BASE_DIR, "logs")
RETENTION_RUNS = 30

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(message)s')

def cleanup():
    logging.info("=================================================")
    logging.info("        Qualys-ME Log Maintenance Tool           ")
    logging.info("=================================================")

    # 1. Ensure log directory exists
    if not os.path.exists(LOG_DIR):
        logging.info(f"[INFO] Creating log directory: {LOG_DIR}")
        os.makedirs(LOG_DIR)

    # 2. Move logs from Slave folder to central logs folder
    logging.info("\n[1/2] Moving logs from Slave folder...")
    log_files = [f for f in os.listdir(SLAVE_DIR) if f.endswith(".log")]

    if not log_files:
        logging.info("[OK] No log files found in Slave folder.")
    else:
        for f in log_files:
            src = os.path.join(SLAVE_DIR, f)
            dst = os.path.join(LOG_DIR, f)
            try:
                # If file exists in destination, append timestamp to prevent overwrite
                if os.path.exists(dst):
                    name, ext = os.path.splitext(f)
                    dst = os.path.join(LOG_DIR, f"{name}_{int(datetime.now().timestamp())}{ext}")
                shutil.move(src, dst)
                logging.info(f"[SUCCESS] Moved {f}")
            except Exception as e:
                logging.error(f"[ERROR] Could not move {f}: {e}")

    # 3. Retention (keep last X days/runs)
    # The original bash used 'tail -n +31' on directories or files.
    # Let's keep the last 30 log files.
    logging.info(f"\n[2/2] Rotating old logs (Retention: {RETENTION_RUNS} runs)...")
    log_paths: List[str] = glob_logs()
    
    if len(log_paths) <= int(RETENTION_RUNS):
        logging.info(f"[OK] Total logs ({len(log_paths)}) within retention limit.")
    else:
        # Sort by modification time
        log_paths.sort(key=os.path.getmtime, reverse=True)
        # Fix: Use simplified slicing and ensure RETENTION_RUNS is int
        limit = int(RETENTION_RUNS)
        to_delete = log_paths[limit:]
        
        for item_path in to_delete:
            abs_path = os.path.abspath(str(item_path))
            try:
                if os.path.isdir(abs_path):
                    shutil.rmtree(abs_path, ignore_errors=True)
                else:
                    os.remove(abs_path)
                logging.info(f"[DELETE] {os.path.basename(abs_path)}")
            except Exception as e:
                logging.error(f"[ERROR] Could not delete {os.path.basename(abs_path)}: {e}")

    logging.info("\n=================================================")
    logging.info("          Log maintenance completed              ")
    logging.info("=================================================")

def glob_logs() -> List[str]:
    # This matches both run folders (YYYY-MM-DD) and individual log files
    paths = glob.glob(os.path.join(LOG_DIR, "*"))
    return paths

if __name__ == "__main__":
    cleanup()
