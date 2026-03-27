import csv
import os
from datetime import datetime

# ================= CONFIG =================
# Dynamic path detection for cross-platform support
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(SCRIPT_DIR, "../../"))
BASE_DIR = os.path.join(PROJECT_ROOT, "Qualys")

INPUT_FILE = os.path.join(BASE_DIR, "Qualys_Cleaned_Report", "ME_Qualys_Vuln_Report.csv")
SANITIZED_DIR = os.path.join(BASE_DIR, "Q_Sanitized", "Qualys_Sanitized")
AUDIT_DIR = os.path.join(PROJECT_ROOT, "logs", "audit")

os.makedirs(SANITIZED_DIR, exist_ok=True)
os.makedirs(AUDIT_DIR, exist_ok=True)

TIMESTAMP = datetime.now().strftime("%Y%m%d_%H%M%S")

SANITIZED_FILE = os.path.join(SANITIZED_DIR, "Qualys_Sanitized_Report.csv")
AUDIT_FILE = os.path.join(AUDIT_DIR, f"Unstructured_Qualys_Rows_{TIMESTAMP}.csv")

# ================= READ RAW LINES =================
with open(INPUT_FILE, "r", encoding="utf-8", errors="ignore") as f:
    raw_lines = f.readlines()

if not raw_lines:
    raise Exception("❌ Input file is empty")

# ================= HEADER =================
header = next(csv.reader([raw_lines[0]]))
EXPECTED_COLS = len(header)

valid_rows = []
bad_rows = []

buffer = ""

# ================= SANITIZE =================
for line_no, line in enumerate(raw_lines, start=1):
    if line_no == 1:
        continue
    buffer += line

    try:
        parsed = next(csv.reader([buffer]))
    except Exception:
        continue

    if len(parsed) == EXPECTED_COLS:
        valid_rows.append(parsed)
        buffer = ""
    else:
        # Still broken → wait for next line
        if buffer.count('"') % 2 == 0:
            bad_rows.append((line_no, buffer))
            buffer = ""

# ================= WRITE SANITIZED FILE =================
with open(SANITIZED_FILE, "w", newline="", encoding="utf-8") as f:
    writer = csv.writer(f, quoting=csv.QUOTE_ALL)
    writer.writerow(header)
    writer.writerows(valid_rows)

# ================= WRITE AUDIT FILE =================
with open(AUDIT_FILE, "w", newline="", encoding="utf-8") as f:
    writer = csv.writer(f)
    writer.writerow(["Line Number", "IP", "QID", "Raw Data"])

    ip_index = header.index("IP") if "IP" in header else -1
    qid_index = header.index("QID") if "QID" in header else -1

    for line_no, raw in bad_rows:
        ip = qid = ""
        try:
            row = next(csv.reader([raw]))
            if ip_index != -1 and len(row) > ip_index:
                ip = row[ip_index]
            if qid_index != -1 and len(row) > qid_index:
                qid = row[qid_index]
        except Exception:
            pass

        writer.writerow([line_no, ip, qid, raw.strip()])

# ================= SUMMARY =================
print("[SUCCESS] Qualys CSV Sanitization Completed")
print(f"File-Sanitized : {SANITIZED_FILE}")
print(f"File-Audit     : {AUDIT_FILE}")
print(f"Stats-Valid    : {len(valid_rows)}")
print(f"Stats-Broken   : {len(bad_rows)}")
