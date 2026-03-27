import pandas as pd
import os
import csv
from datetime import datetime

# ================= CONFIG =================
# Dynamic path detection for cross-platform support
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(SCRIPT_DIR, "../../"))
BASE_DIR = os.path.join(PROJECT_ROOT, "Qualys")

TODAY_FILE = os.path.join(BASE_DIR, "Q_Sanitized", "Qualys_Sanitized", "Qualys_Sanitized_Report.csv")
MASTER_DB = os.path.join(BASE_DIR, "Qualys_Master_DB", "Qualys_Master_DB.csv")
FIXED_DB = os.path.join(BASE_DIR, "Qualys_Master_DB", "Qualys_Fixed_History.csv")
TRACKER_DB = os.path.join(BASE_DIR, "Qualys_Master_DB", "Qualys_Vuln_Status_Tracker.csv")
FIXED_TICKETS_TO_CLOSE = os.path.join(BASE_DIR, "State", "to_be_closed.csv")

NOW = datetime.now()
NOW_STR = NOW.strftime("%Y-%m-%d %H:%M:%S")

# ================= LOAD TODAY =================
today_df = pd.read_csv(TODAY_FILE, dtype=str).fillna("")
today_df["KEY"] = today_df["IP"] + "|" + today_df["QID"]

today_df = today_df.drop_duplicates(subset=["KEY"])

today_keys = set(today_df["KEY"])

# ================= LOAD / INIT MASTER =================
if not os.path.exists(MASTER_DB):
    today_df.to_csv(MASTER_DB, index=False, quoting=csv.QUOTE_ALL)
    print("[NEW] Master DB created")
    master_df = today_df.copy()
else:
    master_df = pd.read_csv(MASTER_DB, dtype=str).fillna("")

master_keys = set(master_df["KEY"])

# ================= LOAD / INIT TRACKER =================
if os.path.exists(TRACKER_DB):
    tracker_df = pd.read_csv(TRACKER_DB, dtype=str).fillna("")
else:
    tracker_df = pd.DataFrame(columns=[
        "KEY", "First_Seen", "Last_Seen",
        "Current_Status", "Previous_Status",
        "Times_Reopened", "Days_Active",
        "Last_Updated"
    ])

tracker_df.set_index("KEY", inplace=True, drop=False)

# ================= PROCESS TODAY VULNS =================
for _, row in today_df.iterrows():
    key = row["KEY"]
    status = row["Vuln Status"]

    if key not in tracker_df.index:
        tracker_df.loc[key] = [
            key,
            NOW_STR,
            NOW_STR,
            status,
            "",
            "0",
            "0",
            NOW_STR
        ]
    else:
        prev_status = tracker_df.loc[key, "Current_Status"]

        tracker_df.loc[key, "Previous_Status"] = prev_status
        tracker_df.loc[key, "Current_Status"] = status
        tracker_df.loc[key, "Last_Seen"] = NOW_STR
        tracker_df.loc[key, "Last_Updated"] = NOW_STR

        if prev_status == "Fixed" and status == "Reopened":
            tracker_df.loc[key, "Times_Reopened"] = str(
                int(tracker_df.loc[key, "Times_Reopened"]) + 1
            )

# ================= IDENTIFY FIXED =================
# 1. Vulns missing from today's report (Implicitly Fixed)
implicitly_fixed_keys = master_keys - today_keys

# 2. Vulns explicitly marked as "Fixed" in today's report (Explicitly Fixed)
explicitly_fixed_keys = set(today_df[today_df["Vuln Status"] == "Fixed"]["KEY"])

all_fixed_keys = implicitly_fixed_keys | explicitly_fixed_keys

# Build the closure list
fixed_now_df = master_df[master_df["KEY"].isin(all_fixed_keys)].copy()

# Add any vulns that are in today's report as Fixed but weren't in Master (unlikely but possible)
new_fixed_today = today_df[today_df["KEY"].isin(explicitly_fixed_keys) & ~today_df["KEY"].isin(master_keys)]
if not new_fixed_today.empty:
    fixed_now_df = pd.concat([fixed_now_df, new_fixed_today], ignore_index=True)

if not fixed_now_df.empty:
    fixed_now_df["Fixed Date"] = NOW_STR

    if os.path.exists(FIXED_DB):
        fixed_hist_df = pd.read_csv(FIXED_DB, dtype=str).fillna("")
        fixed_hist_df = fixed_hist_df[~fixed_hist_df["KEY"].isin(fixed_now_df["KEY"])]
        fixed_hist_df = pd.concat([fixed_hist_df, fixed_now_df], ignore_index=True)
    else:
        fixed_hist_df = fixed_now_df

    fixed_hist_df.to_csv(FIXED_DB, index=False, quoting=csv.QUOTE_ALL)

    # Update tracker status to Fixed
    for k in all_fixed_keys:
        if k in tracker_df.index:
            tracker_df.loc[k, "Previous_Status"] = tracker_df.loc[k, "Current_Status"]
            tracker_df.loc[k, "Current_Status"] = "Fixed"
            tracker_df.loc[k, "Last_Updated"] = NOW_STR

    # Save the keys of vulnerabilities to be closed in ME
    fixed_now_df[["KEY", "Fixed Date"]].to_csv(FIXED_TICKETS_TO_CLOSE, index=False, quoting=csv.QUOTE_ALL)
    print(f"📋 Closing list saved: {FIXED_TICKETS_TO_CLOSE}")
else:
    if os.path.exists(FIXED_TICKETS_TO_CLOSE):
        os.remove(FIXED_TICKETS_TO_CLOSE)

# ================= CLEAN MASTER DB =================
# Master DB will now ONLY contain Active/New/Reopened vulnerabilities
master_df = master_df[~master_df["KEY"].isin(all_fixed_keys)]

# Only add rows from today that are NOT fixed
active_today_df = today_df[today_df["Vuln Status"] != "Fixed"]
master_df = master_df[~master_df["KEY"].isin(active_today_df["KEY"])]
master_df = pd.concat([master_df, active_today_df], ignore_index=True)

# ================= SAVE FILES =================
master_df.to_csv(MASTER_DB, index=False, quoting=csv.QUOTE_ALL)
tracker_df.reset_index(drop=True).to_csv(TRACKER_DB, index=False, quoting=csv.QUOTE_ALL)

# ================= SUMMARY =================
print("[SUCCESS] Master DB updated (Active/New/Reopened only)")
print(f"Stats-Fixed     : {len(all_fixed_keys)}")
print(f"Stats-Active    : {len(master_df)}")
print(f"Stats-Tracker   : {len(tracker_df)}")
