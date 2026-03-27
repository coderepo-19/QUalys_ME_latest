import os
import subprocess
import sys
import datetime

# ================= CONFIG =================
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
MASTER_DIR = os.path.join(BASE_DIR, "scripts", "Master")
SLAVE_DIR = os.path.join(BASE_DIR, "scripts", "Slave")
LOG_DIR = os.path.join(BASE_DIR, "logs")

# Scripts order
SCRIPTS = [
    "00_Setup_Environment.py",
    "cleanup_logs.py",
    "01_Download_Qualys_Vuln_Data_1.py",
    "02_qualys_clean_csv_2.py",
    "03_Qualys_Sanitized_Data_3.py",
    "04_Qualys_Master_DB_4.py",
    "05_Daily_Ticket_Generation_5.py"
]

def run_master():
    run_ts = datetime.datetime.now().strftime("%Y-%m-%d")
    run_log_dir = os.path.join(LOG_DIR, run_ts)
    os.makedirs(run_log_dir, exist_ok=True)

    master_log_path = os.path.join(run_log_dir, "master.log")
    
    with open(master_log_path, "a") as master_log:
        def log(msg):
            print(msg)
            master_log.write(f"{datetime.datetime.now()} {msg}\n")

        log("=================================================")
        log(f"[START] Qualys-ME Master Pipeline | {datetime.datetime.now()}")
        log("=================================================")

        # Execute scripts in sequence
        for script in SCRIPTS:
            script_path = os.path.join(SLAVE_DIR, script)
            script_name = os.path.splitext(script)[0]
            script_log_path = os.path.join(run_log_dir, f"{script_name}.log")

            log(f"-------------------------------------------------")
            log(f"[RUNNING] {script}")
            log(f"[LOG] {script_log_path}")
            
            if not os.path.exists(script_path):
                log(f"[ERROR] Script not found: {script_path}")
                sys.exit(1)

            try:
                # Force UTF-8 for subprocesses on Windows to prevent encoding errors
                env = os.environ.copy()
                env["PYTHONIOENCODING"] = "utf-8"
                
                with open(script_log_path, "a", encoding="utf-8") as s_log:
                    result = subprocess.run(
                        [sys.executable, script_path],
                        stdout=s_log,
                        stderr=subprocess.STDOUT,
                        text=True,
                        env=env
                    )
                
                if result.returncode == 0:
                    log(f"[SUCCESS] {script} completed")
                else:
                    log(f"[FAILED] {script} exited with code {result.returncode}")
                    log(f"Check logs for details: {script_log_path}")
                    sys.exit(1)
            except Exception as e:
                log(f"[CRITICAL] Failed to execute {script}: {e}")
                sys.exit(1)

        log("=================================================")
        log(f"[COMPLETE] {datetime.datetime.now()}")
        log("=================================================")

if __name__ == "__main__":
    run_master()
