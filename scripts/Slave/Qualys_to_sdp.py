
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import csv
import json
import time
import argparse
import sys
import re
import html
import os
import urllib.parse
import requests
import random
from dotenv import load_dotenv
from datetime import datetime, timedelta, timezone
from typing import Dict, Any, Optional, Tuple
# Load environment variables
load_dotenv(os.path.join(os.path.dirname(__file__), "..", "..", "Config", ".env"))

STATE_REF: Dict[str, dict] = {}

# ------------------------------
# Qualys columns (match your header)
# ------------------------------
COLUMNS = {
    "ip": "IP",
    "dns": "DNS",
    "netbios": "NetBIOS",
    "host_id": "QG Host ID",
    "interfaces": "IP Interfaces",
    "tracking": "Tracking Method",
    "os": "OS",
    "ip_status": "IP Status",
    "qid": "QID",
    "title": "Title",
    "vuln_status": "Vuln Status",
    "type": "Type",
    "severity": "Severity",  # used for Priority (1..5)
    "port": "Port",
    "protocol": "Protocol",
    "fqdn": "FQDN",
    "ssl": "SSL",
    "first_detected": "First Detected",
    "last_detected": "Last Detected",
    "times_detected": "Times Detected",
    "date_last_fixed": "Date Last Fixed",
    "first_reopened": "First Reopened",
    "last_reopened": "Last Reopened",
    "times_reopened": "Times Reopened",
    "cve": "CVE ID",
    "vendor_ref": "Vendor Reference",
    "bugtraq": "Bugtraq ID",
    "cvss": "CVSS",
    "cvss_base": "CVSS Base",
    "cvss_temporal": "CVSS Temporal",
    "cvss_env": "CVSS Environment",
    "cvss31": "CVSS3.1",
    "cvss31_base": "CVSS3.1 Base",
    "cvss31_temp": "CVSS3.1 Temporal",
    "threat": "Threat",
    "impact": "Impact",
    "solution": "Solution",
    "exploitability": "Exploitability",
    "malware": "Associated Malware",
    "results": "Results",
    "pci_vuln": "PCI Vuln",
    "ticket_state": "Ticket State",
    "instance": "Instance",
    "os_cpe": "OS CPE",
    "category": "Category",
    "associated_ags": "Associated Ags",
    "associated_tags": "Associated Tags",
    "qds": "QDS",
    "ars": "ARS",
    "acs": "ACS",
    "trurisk": "TruRisk Score",
    "mitre_tactic": "MITRE ATT&CK Tactic Name",
    "mitre_tech": "MITRE ATT&CK Technique Name",
    "mitre_tactic_id": "MITRE ATT&CK Tactic ID",
    "mitre_tech_id": "MITRE ATT&CK Technique ID",
    "key": "KEY",
    "vuln_state": "Vuln State",
    "first_seen": "First Seen",
    "last_seen": "Last Seen",
}

# ------------------------------
# OS → Category/Subcategory/Item mapping (optional)
# ------------------------------
OS_TO_CSI = {
    "Windows 10": ("OS", "Windows", "Windows 10"),
    "Windows 11": ("OS", "Windows", "Windows 11"),
    "Windows Server 2019": ("OS", "Windows Server", "2019"),
    "Windows Server 2022": ("OS", "Windows Server", "2022"),
    "Linux": ("OS", "Linux", "Generic"),
    "Ubuntu": ("OS", "Linux", "Ubuntu"),
    "RHEL": ("OS", "Linux", "RHEL"),
}

# ------------------------------
# Severity (1..5) → Priority name (your labels)
# 1→Very Low, 2→Low, 3→Medium, 4→High, 5→Critical
# ------------------------------
def severity_to_bucket(sev_val: Optional[str]) -> str:
    if not sev_val or not sev_val.strip():
        return "Medium"
    s = str(sev_val).strip()
    try:
        n = int(float(s))
    except ValueError:
        sl = s.lower()
        if "very" in sl and "low" in sl: return "Very Low"
        if "critical" in sl: return "Critical"
        if "high" in sl:     return "High"
        if "medium" in sl:   return "Medium"
        if "low" in sl:      return "Low"
        return "Medium"
    return ["Very Low","Low","Medium","High","Critical"][min(max(n,1),5)-1]

# ------------------------------
# SDP static defaults fallback
# ------------------------------
SDP_MODE = "Web"
SDP_TEMPLATE = "Default Request"
SDP_REQUEST_TYPE = "Incident"
SDP_STATUS_OPEN = "Open"

# Requester is OPTIONAL. If None, omit; SDP uses OAuth user.
SDP_REQUESTER_EMAIL: Optional[str] = None
EMBED_RUN_NUMBER_IN_SUBJECT = True

# Routing rules loaded from external JSON at runtime
ROUTING_RULES: dict = {}

def load_routing_rules(path: Optional[str]) -> dict:
    """Load routing_rules.json. Returns empty dict if path not given or missing."""
    if not path:
        return {}
    if not os.path.exists(path):
        print(f"[WARN] routing_rules.json not found at {path} — using built-in defaults", file=sys.stderr)
        return {}
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

# ------------------------------
# Technician Assignment (Round-Robin / Random)
# ------------------------------
ASSIGNMENT_MODE = os.getenv("SDP_ASSIGNMENT_MODE", "None")
TECH_LIST_RAW = os.getenv("SDP_TECHNICIAN_LIST", "")
TECHNICIAN_LIST = [t.strip() for t in TECH_LIST_RAW.split(",") if t.strip()]

def get_rr_state_path(state_path: str) -> str:
    """Derive round_robin_state.json path from main state file path."""
    base = os.path.dirname(state_path)
    return os.path.join(base, "round_robin_state.json")

def load_rr_index(path: str) -> int:
    if not os.path.exists(path):
        return 0
    try:
        with open(path, "r") as f:
            return json.load(f).get("next_index", 0)
    except:
        return 0

def save_rr_index(path: str, index: int):
    try:
        with open(path, "w") as f:
            json.dump({"next_index": index}, f)
    except:
        pass

def get_assigned_technician(rr_path: str) -> Optional[str]:
    """Returns the next technician based on ASSIGNMENT_MODE."""
    if not TECHNICIAN_LIST:
        return None
        
    if ASSIGNMENT_MODE == "Random":
        return random.choice(TECHNICIAN_LIST)
        
    if ASSIGNMENT_MODE == "RoundRobin":
        idx = load_rr_index(rr_path)
        if idx >= len(TECHNICIAN_LIST):
            idx = 0
        tech = TECHNICIAN_LIST[idx]
        save_rr_index(rr_path, (idx + 1) % len(TECHNICIAN_LIST))
        return tech
        
    return None

def resolve_routing(row: Dict[str, str], sev_bucket: str) -> dict:
    """
    Match the vulnerability row against ROUTING_RULES.
    Checks fields listed in rule["match_fields"] (e.g. category, title, os)
    against each rule's keywords. First match wins.
    Falls back to defaults if no rule matches.
    Returns a dict with all routing fields.
    """
    rules    = ROUTING_RULES.get("rules", [])
    defaults = ROUTING_RULES.get("defaults", {})
    sev_map  = ROUTING_RULES.get("severity_map", {})
    
    # Get severity-based defaults
    sev_info = sev_map.get(sev_bucket, {})

    resolved = {
        "requester_name": defaults.get("requester_name", ""),
        "category":     defaults.get("category", ""),
        "subcategory":  defaults.get("subcategory", ""),
        "item":         defaults.get("item", ""),
        "group":        defaults.get("group", ""),
        "site":         defaults.get("site", ""),
        "technician":   defaults.get("technician", ""),
        "request_type": defaults.get("request_type", "Incident"),
        "status":       defaults.get("status", "Open"),
        "mode":         defaults.get("mode", "E-Mail"),
        "template":     defaults.get("template", "Default Request"),
        "impact":       defaults.get("impact", ""),
        "priority":     sev_info.get("priority", "Medium"),
        "urgency":      sev_info.get("urgency", "Medium"),
        "level":        sev_info.get("level", ""),
        "due_days":     sev_info.get("due_days", 30),
        "emails":       sev_info.get("emails", [])
    }

    for rule in rules:
        if "keywords" not in rule:
            continue
        match_fields = rule.get("match_fields", ["category", "title"])
        signals = [(get(row, f) or "").lower() for f in match_fields]
        
        # If any keyword matches any of the signal fields
        if any(kw.lower() in sig for kw in rule["keywords"] for sig in signals):
            # Override resolved with rule-specific values if they exist
            for key in ["category", "subcategory", "item", "group", "site", "technician", "request_type", "mode", "impact"]:
                if key in rule:
                    resolved[key] = rule[key]
            
            # Allow rule-specific severity overrides
            sev_overrides = rule.get("severity_override", {}).get(sev_bucket, {})
            for key in ["priority", "urgency", "level", "emails"]:
                if key in sev_overrides:
                    resolved[key] = sev_overrides[key]
            break

    return resolved

# ------------------------------
# Helpers
# ------------------------------
def get(row: Dict[str, str], key: str) -> Optional[str]:
    col = COLUMNS.get(key)
    val = row.get(col) if col else None
    if val is None: return None
    v = val.strip()
    return v if v != "" else None

def now_ms() -> int: return int(time.time() * 1000)

def plus_days_ms(days: int) -> int:
    dt = datetime.now(timezone.utc) + timedelta(days=days)
    return int(dt.timestamp() * 1000)

def os_to_csi(os_name: Optional[str]) -> Tuple[str, str, str]:
    if not os_name: return ("OS", "Unknown", "Generic")
    for key, triple in OS_TO_CSI.items():
        if key.lower() in os_name.lower(): return triple
    return ("OS", os_name, "Generic")

def is_active(row: Dict[str, str]) -> bool:
    status = (get(row, "vuln_status") or get(row, "vuln_state") or "").lower()
    if status == "": return True
    active_values = {"active", "new", "reopened", "re-opened", "open"}
    fixed_values  = {"fixed", "resolved", "false positive", "ignored", "suppressed", "closed"}
    if status in fixed_values: return False
    return status in active_values

def subject(
    row: Dict[str, str],
    identity_key: str,
    state: Dict[str, dict]
) -> str:
    ip = get(row, "ip") or "UnknownIP"
    qid = get(row, "qid") or "UnknownQID"
    title = get(row, "title") or "Untitled"

    ticket_count = state.get(identity_key, {}).get("ticket_created_count", 1)

    subj = f"Qualys | {ip} | {qid} | {title} | TC#: {str(ticket_count)}"
    return str(subj)[:250]  # type: ignore[index]

# ------------------------------
# Pretty, clickable HTML description
# ------------------------------
def description_html(row: Dict[str, str]) -> str:
    def esc(x: Optional[str]) -> str: return html.escape(x or "")

    def linkify_urls(text: str) -> str:
        # Linkify http/https safely (lambda → no backrefs)
        return re.sub(
            r'(https?://[^\s<>"]+)',
            lambda m: '<a href="' + m.group(1) + '" target="_blank" rel="noopener">' + m.group(1) + '</a>',
            text or ""
        )

    def cve_links(cve_text: Optional[str]) -> str:
        if not cve_text:
            return ""
        parts = [p.strip() for p in re.split(r'[,\s]+', cve_text) if p.strip()]
        links = []
        for p in parts:
            if p.upper().startswith("CVE-"):
                url = "https://nvd.nist.gov/vuln/detail/" + p
                links.append('<a href="' + url + '" target="_blank" rel="noopener">' + esc(p) + '</a>')
            else:
                links.append(esc(p))
        return ", ".join(links)

    sev_raw  = (get(row, "severity") or "").strip()
    sev_bucket = severity_to_bucket(sev_raw)

    sev_colors = {
        "Very Low": "#7b8893",
        "Low":      "#2e7df6",
        "Medium":   "#ff9f40",
        "High":     "#f44336",
        "Critical": "#b00020",
    }
    sev_color = sev_colors.get(sev_bucket, "#2e7df6")

    title_text = esc(get(row, "title"))
    ip         = esc(get(row, "ip"))
    vuln_status     = esc(get(row, "vuln_status") or "")
    dns        = esc(get(row, "dns"))
    os_name    = esc(get(row, "os"))
    qid        = esc(get(row, "qid"))
    cve_text   = get(row, "cve") or ""
    vendor_ref = linkify_urls(esc(get(row, "vendor_ref") or ""))
    bugtraq    = esc(get(row, "bugtraq") or "")
    cvss       = esc(get(row, "cvss") or "")
    cvss31     = esc(get(row, "cvss31") or "")
    qds        = esc(get(row, "qds") or "")
    trurisk    = esc(get(row, "trurisk") or "")
    first_det  = esc(get(row, "first_detected") or "")
    last_det   = esc(get(row, "last_detected") or "")
    times_det  = esc(get(row, "times_detected") or "")
    times_reopened  = esc(get(row, "times_reopened") or "0")
    last_reopened   = esc(get(row, "last_reopened") or "")

    threat   = linkify_urls(esc(get(row, "threat")))
    impact   = linkify_urls(esc(get(row, "impact")))
    results  = linkify_urls(esc(get(row, "results")))
    solution = linkify_urls(esc(get(row, "solution")))

    # Quick actions (CVE → NVD, Title → Google)
    first_cve = ""
    for p in re.split(r'[,\s]+', cve_text):
        p = p.strip()
        if p.upper().startswith("CVE-"):
            first_cve = p
            break

    cve_btn = (
        '<a href="https://nvd.nist.gov/vuln/detail/{c}" '
        'target="_blank" rel="noopener">🔗 NVD: {c}</a>'
    ).format(c=esc(first_cve)) if first_cve else ""

    google_btn = (
        '<a href="https://www.google.com/search?q={q}" '
        'target="_blank" rel="noopener">🔎 Google Title</a>'
    ).format(q=urllib.parse.quote_plus(get(row, "title") or ""))

    # Table row builder
    def row_html(label: str, value: str) -> str:
        return (
            '<tr>'
              '<th style="width:190px; min-width:150px; padding:10px 12px; text-align:left;'
                        'background:#f7f9fc; font-weight:700; color:#374151; vertical-align:top;'
                        'border:1px solid #e5e7eb; word-break:break-word;">{}</th>'
              '<td style="padding:10px 14px; border:1px solid #e5e7eb; color:#111827;'
                        'font-size:15px; line-height:1.5; word-break:break-word; white-space:normal;">{}</td>'
            '</tr>'
        ).format(html.escape(label), value)

    rows_html = [
        row_html("IP", ip),
        row_html("Qualys Vulnerability Status", vuln_status),
        row_html("DNS", dns),
        row_html("OS", os_name),
        row_html("QID", qid),
        row_html("Severity (1–5)", esc(sev_raw)),
        row_html("Times Detected", times_det),
        row_html("CVE ID", cve_links(cve_text)),
        row_html("Vendor Reference", vendor_ref),
        row_html("Bugtraq ID", bugtraq),
        row_html("CVSS", cvss),
        row_html("CVSS3.1", cvss31),
        row_html("QDS", qds),
        row_html("TruRisk Score", trurisk),
        row_html("First Detected", first_det),
        row_html("Last Detected", last_det),
        row_html("Times Detected", times_det),
        row_html("Times Reopened", times_reopened),
    ]

    # Title header (safe .format placeholders)
    header_html = (
        '<div style="display:flex; align-items:flex-start; gap:12px; margin:0 0 12px 0;">'
          '<div style="flex:1 1 auto; padding:12px 14px; background:#eef5ff; border:1px solid #cfe0ff; border-radius:6px;">'
            '<div style="font-size:13px; color:#1f3b73; text-transform:uppercase; letter-spacing:.4px; margin-bottom:4px;">'
              '🧩 Vulnerability Title'
            '</div>'
            '<div style="font-weight:700; font-size:16px; line-height:1.5; color:#0b3d91; word-break:break-word;">{title}</div>'
          '</div>'
          '<div style="flex:0 0 auto; display:flex; flex-direction:column; gap:8px; min-width:160px;">'
            '<div title="Severity" style="display:inline-block; padding:8px 10px; border-radius:18px;'
                                     'background:{sev_color}; color:#fff; font-weight:700; text-align:center;">'
              '⚠️ {sev_bucket}'
            '</div>'
            '<div style="display:inline-block; padding:6px 10px; border-radius:18px; background:#f1f5f9; color:#0f172a;">'
              '🆔 QID: {qid}'
            '</div>'
          '</div>'
        '</div>'
    ).format(title=title_text, sev_color=sev_color, sev_bucket=html.escape(sev_bucket), qid=qid)

    actions_html = '<div style="margin-bottom:12px;">' + cve_btn + google_btn + '</div>'

    table_html = (
        '<table style="border-collapse:collapse; width:100%; table-layout:fixed; border:1px solid #e5e7eb; background:#fff;">'
          '<tbody>' + ''.join(rows_html) + '</tbody>'
        '</table>'
    )

    threat_html = (
        '<h4 style="margin:18px 0 6px; font-size:15px; color:#0f172a;">🔎 Threat</h4>'
        '<pre style="white-space:pre-wrap; background:#fafafa; border:1px solid #eee; padding:10px 12px; border-radius:6px;'
                    'font-size:14.5px; line-height:1.55; overflow-wrap:anywhere;">' + threat + '</pre>'
    )
    impact_html = (
        '<h4 style="margin:16px 0 6px; font-size:15px; color:#0f172a;">⚠️ Impact</h4>'
        '<pre style="white-space:pre-wrap; background:#fff7ed; border:1px solid #fed7aa; padding:10px 12px; border-radius:6px;'
                    'font-size:14.5px; line-height:1.55; overflow-wrap:anywhere;">' + impact + '</pre>'
    )
    results_html = (
        '<h4 style="margin:16px 0 6px; font-size:15px; color:#0f172a;">🧪 Results</h4>'
        '<pre style="white-space:pre-wrap; background:#f8fafc; border:1px solid #e2e8f0; padding:10px 12px; border-radius:6px;'
                    'font-size:14.5px; line-height:1.55; overflow-wrap:anywhere;">' + results + '</pre>'
    )
    solution_html = (
        '<h4 style="margin:16px 0 6px; font-size:15px; color:#0f172a;">🛠️ Solution</h4>'
        '<pre style="white-space:pre-wrap; background:#ecfdf5; border:1px solid #a7f3d0; padding:10px 12px; border-radius:6px;'
                    'font-size:14.5px; line-height:1.55; overflow-wrap:anywhere;">' + solution + '</pre>'
    )
    refs_html = (
        '<h4 style="margin:16px 0 6px; font-size:15px; color:#0f172a;">🔗 References</h4>'
        '<ul style="margin:0 0 6px 18px; padding:0; font-size:14.5px; line-height:1.55;">'
          '<li><b>CVE:</b> ' + str(cve_links(cve_text)) + '</li>'
          '<li><b>Vendor Reference:</b> ' + str(vendor_ref) + '</li>'
          '<li><b>Bugtraq ID:</b> ' + str(bugtraq) + '</li>'
        '</ul>'
    )

    return (
        '<div style="font-family:Segoe UI, system-ui, -apple-system, Roboto, Arial, sans-serif; color:#111827;">'
          + header_html +
          actions_html +
          table_html +
          threat_html +
          impact_html +
          results_html +
          solution_html +
          refs_html +
        '</div>'
    )

# ------------------------------
# Build payload (with optional fields; picklists safe)
# ------------------------------
def build_payload(
    row: Dict[str, str],
    run_num: Optional[int],
    requester_email: Optional[str],
    map_category_from_os: bool,
    static_category: Optional[str],
    static_subcategory: Optional[str],
    static_item: Optional[str],
    add_ip_as_asset: bool,
    asset_id_column: Optional[str],
    udf_qid_name: Optional[str],
    udf_ip_name: Optional[str],
    udf_run_num_name: Optional[str],
    assigned_technician: Optional[str],
    urgency_name: Optional[str],
    no_urgency: bool,
    priority_name: Optional[str],
    no_priority: bool,
    level_name: Optional[str],
    no_level: bool
) -> Dict[str, Any]:

    if not is_active(row):
        raise ValueError("Not active/new/reopened; skipping")

    sev_bucket = severity_to_bucket(get(row, "severity"))

    # Dynamic routing: all ME fields from routing_rules.json
    routing = resolve_routing(row, sev_bucket)

    # CLI static overrides still respected if provided
    if static_category:    routing["category"]    = static_category
    if static_subcategory: routing["subcategory"] = static_subcategory
    if static_item:        routing["item"]        = static_item

    req: Dict[str, Any] = {
        "subject":      subject(row, identity_key(row), STATE_REF),
        "description":  description_html(row),
    }

    # Add picklists ONLY if they have values
    if routing.get("status"):       req["status"]       = {"name": routing["status"]}
    if routing.get("request_type"): req["request_type"] = {"name": routing["request_type"]}
    if routing.get("template"):     req["template"]     = {"name": routing["template"]}
    if routing.get("mode"):         req["mode"]         = {"name": routing["mode"]}
    if routing.get("site"):         req["site"]         = {"name": routing["site"]}
    if routing.get("group"):        req["group"]        = {"name": routing["group"]}
    
    # Priority: Assigned technician > Routing > Default
    tech_to_use = assigned_technician or routing.get("technician")
    if tech_to_use:
        if "@" in str(tech_to_use):
            req["technician"] = {"email_id": tech_to_use}
        else:
            req["technician"] = {"name": tech_to_use}

    if routing.get("category"):     req["category"]     = {"name": routing["category"]}
    if routing.get("subcategory"):  req["subcategory"]  = {"name": routing["subcategory"]}
    if routing.get("item"):         req["item"]         = {"name": routing["item"]}
    
    if routing.get("emails"):
        req["email_ids_to_notify"] = routing["emails"]
        
    if routing["impact"]:
        req["impact"] = {"name": routing["impact"]}

    # Priority / Level / Urgency from routing (or CLI overrides)
    if not no_priority:
        if priority_name:
            req["priority"] = {"name": priority_name}
        elif routing["priority"]:
            req["priority"] = {"name": routing["priority"]}

    if not no_urgency:
        if urgency_name:
            req["urgency"] = {"name": urgency_name}
        elif routing["urgency"]:
            req["urgency"] = {"name": routing["urgency"]}
            
    if not no_level:
        if level_name:
            req["level"] = {"name": level_name}
        elif routing["level"]:
            req["level"] = {"name": routing["level"]}


    # (category/subcategory/item already set via routing above)

    # requester optional
    if requester_email:
        req["requester"] = {"email_id": requester_email}
    elif routing.get("requester_name"):
        req["requester"] = {"name": routing["requester_name"]}

    # Impact short text (sanitize for SDP)
    impact_text = get(row, "impact")
    if impact_text:
        clean_impact = re.sub(r'[^a-zA-Z0-9 .,;:()\-_/]', ' ', str(impact_text))
        req["impact_details"] = str(clean_impact).strip()[:200]  # type: ignore[index]

    # Resolution
    sol = get(row, "solution")
    if sol:
        req["resolution"] = {"content": sol}

    # Assets (optional)
    assets_list = []
    if asset_id_column:
        asset_id_val = row.get(asset_id_column)
        if asset_id_val and asset_id_val.strip():
            assets_list.append({"id": asset_id_val.strip()})
    elif add_ip_as_asset:
        ip_val = get(row, "ip")
        if ip_val:
            assets_list.append({"name": ip_val})
    if assets_list:
        req["assets"] = assets_list

    # UDFs (optional): include only if API names provided
    udf = {}
    qid_val = get(row, "qid")
    ip_val = get(row, "ip")
    if udf_qid_name and qid_val:
        udf[udf_qid_name] = "QID:" + qid_val
    if udf_ip_name and ip_val:
        udf[udf_ip_name] = "IP:" + ip_val
    if udf_run_num_name and run_num is not None:
        udf[udf_run_num_name] = str(run_num)
    if udf:
        req["udf_fields"] = udf

    return {"request": req}

# ------------------------------
# SDP HELPERS
# ------------------------------
def get_ticket_status(base_url: str, token: str, sdp_id: str, timeout: int = 30) -> Optional[str]:
    """
    Fetches the current status of an SDP ticket by ID.
    Returns the status name string (e.g. 'Open', 'Closed', 'On Hold', 'Resolved')
    or None if the request fails.
    """
    headers = {
        "Accept": "application/vnd.manageengine.sdp.v3+json",
        "Authorization": f"Zoho-oauthtoken {token}",
    }
    url = f"{base_url}/{sdp_id}"
    try:
        r = requests.get(url, headers=headers, timeout=timeout)
        if r.status_code == 200:
            return r.json().get("request", {}).get("status", {}).get("name")
    except Exception:
        pass
    return None

def close_ticket(base_url: str, token: str, sdp_id: str, timeout: int = 60) -> requests.Response:
    """
    Sets the status of an existing SDP ticket to 'Closed'.
    """
    headers = {
        "Accept": "application/vnd.manageengine.sdp.v3+json",
        "Authorization": f"Zoho-oauthtoken {token}",
        "Content-Type": "application/x-www-form-urlencoded",
    }
    
    # Payload to close the ticket
    close_payload = {
        "request": {
            "status": {"name": "Closed"},
            "resolution": {"content": "Vulnerability marked as FIXED in Qualys scan."}
        }
    }
    
    input_data = {"input_data": json.dumps(close_payload, ensure_ascii=False)}
    
    # SDP v3 API uses PUT for updates: /api/v3/requests/{id}
    url = f"{base_url}/{sdp_id}"
    r = requests.put(url, headers=headers, data=input_data, timeout=timeout)
    return r

def reopen_ticket(base_url: str, token: str, sdp_id: str, new_subject: str, timeout: int = 30) -> requests.Response:
    headers = {
        "Accept": "application/vnd.manageengine.sdp.v3+json",
        "Authorization": f"Zoho-oauthtoken {token}",
        "Content-Type": "application/x-www-form-urlencoded",
    }
    
    # Payload to reopen the ticket and update the subject with the new TC count
    reopen_payload = {
        "request": {
            "status": {"name": "Open"},
            "subject": new_subject,
            "description": f"This vulnerability was previously marked as fixed but was detected again by Qualys.<br>The Ticket Count (TC) has been incremented.<br><br>Timestamp: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}"
        }
    }
    
    input_data = {"input_data": json.dumps(reopen_payload, ensure_ascii=False)}
    
    url = f"{base_url}/{sdp_id}"
    r = requests.put(url, headers=headers, data=input_data, timeout=timeout)
    return r

def post_sdp(base_url: str, token: str, payload: Dict[str, Any], timeout: int = 60, depth: int = 0) -> requests.Response:
    """
    POST to SDP. If it fails with a field error (400), attempt to drop that field
    and retry recursively (up to 5 times) to ensure the ticket is created
    with at least the valid fields.
    
    Cascading dependencies:
     - If 'subcategory' fails, also drop 'category' and 'item'
       (ME requires subcategory when category is set)
     - If 'category' fails, also drop 'subcategory' and 'item'
    """
    # Fields that are linked and must be dropped together
    CASCADE_DROP = {
        "subcategory": ["subcategory", "category", "item"],
        "category":    ["category", "subcategory", "item"],
        "item":        ["item"],
        "impact":      ["impact"],
    }

    headers = {
        "Accept": "application/vnd.manageengine.sdp.v3+json",
        "Authorization": f"Zoho-oauthtoken {token}",
        "Content-Type": "application/x-www-form-urlencoded",
    }
    
    # payload is already {"request": {...}} from build_payload()
    input_data = {"input_data": json.dumps(payload, ensure_ascii=False)}
    r = requests.post(base_url, headers=headers, data=input_data, timeout=timeout)
    
    # If 400 error, check if it's a field mismatch
    if r.status_code == 400 and depth < 5:
        try:
            res = r.json()
            error_msgs = res.get("response_status", {}).get("messages", [])
            
            # The actual fields are inside payload["request"]
            req_obj = payload.get("request", {})
            
            # Collect fields to drop (including cascades)
            fields_to_drop = set()
            for msg in error_msgs:
                fld = msg.get("field")
                if not fld:
                    continue
                # Drop the failing field and any fields that cascade from it
                cascade = CASCADE_DROP.get(fld, [fld])
                for cf in cascade:
                    if cf in req_obj:
                        fields_to_drop.add(cf)
            
            if fields_to_drop:
                print(f"[RETRY {depth+1}] Dropping failing fields from SDP request: {sorted(fields_to_drop)}", file=sys.stderr)
                for fld in fields_to_drop:
                    req_obj.pop(fld, None)
                
                # Recursive retry with the updated payload
                return post_sdp(base_url, token, payload, timeout, depth + 1)
                
        except Exception as e:
            print(f"[RETRY] Failed to parse error response: {e}", file=sys.stderr)
            
    return r
    
# ------------------------------
# Check if ticket already exists in SDP
# ------------------------------
def ticket_exists(base_url: str, token: str, key: str) -> Optional[str]:

    # Remove /search as it's not applicable for all SDP V3 versions/Cloud
    search_url = base_url

    headers = {
        "Accept": "application/vnd.manageengine.sdp.v3+json",
        "Authorization": f"Zoho-oauthtoken {token}"
    }

    params = {
        "input_data": json.dumps({
            "list_info": {
                "search_criteria": [
                    {
                        "field": "subject",
                        "condition": "contains",
                        "value": f"{key.split('|')[0]} | {key.split('|')[1]}"
                    }
                ],
                "fields_required": ["id"]
            }
        })
    }

    try:
        r = requests.get(search_url, headers=headers, params=params, timeout=30)

        if r.status_code == 200:
            data = r.json()
            requests_list = data.get("requests", [])
            if requests_list:
                # Return the ID of the first match
                return str(requests_list[0].get("id"))
    except Exception:
        pass

    return None

# ------------------------------
# State & utils
# ------------------------------
def load_state(path: Optional[str]) -> dict:
    if not path or not os.path.exists(path):
        return {}

    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def save_state(path: Optional[str], state: dict):
    if not path:
        return
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(state, f, indent=2)
    except Exception as e:
        print(f"Warning: failed to save state: {e}", file=sys.stderr)

def close_fixed_tickets(csv_path: str, base_url: str, token: str, statefile: str, rate: float):
    """
    Reads the list of fixed vulnerabilities and closes their SDP tickets if they exist in state.
    """
    if not os.path.exists(csv_path):
        return

    state = load_state(statefile)
    closed = 0
    failed = 0
    
    print(f"\n=== Closing Fixed Vulnerabilities ===")
    
    with open(csv_path, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            key = row.get("KEY")
            if not key or key not in state:
                continue
                
            entry = state[key]
            sdp_id = entry.get("sdp_id")
            if not sdp_id:
                continue

            # Fetch current ticket status from SDP
            current_status = get_ticket_status(base_url, token, sdp_id)
            if current_status is None:
                print(f"[CLOSE] Could not fetch status for ticket {sdp_id} ({key}) — skipping")
                continue

            # Only close if ticket is currently 'Open'
            if current_status.lower() != "open":
                print(f"[CLOSE] Skipping ticket {sdp_id} ({key}) — status is '{current_status}' (not Open)")
                # Still mark as FIXED in our state so we don't keep trying
                entry["status"] = "FIXED"
                entry["last_closed_at"] = datetime.now().isoformat()
                entry["skip_reason"] = f"SDP status was '{current_status}' — not auto-closed"
                continue

            print(f"[CLOSE] Ticket {sdp_id} for {key}...", end=" ", flush=True)
            resp = close_ticket(base_url, token, sdp_id)
            
            if resp.status_code in (200, 201):
                print(" - Closed")
                entry["status"] = "FIXED"
                entry["last_closed_at"] = datetime.now().isoformat()
                closed += 1
            else:
                print(f"FAILED: {resp.text[:200]}")
                failed += 1
            
            time.sleep(rate)

    save_state(statefile, state)
    print(f"Summary: {closed} tickets closed, {failed} failures.\n")

def identity_key(row: Dict[str, str]) -> str:
    ip = get(row, "ip")
    qid = get(row, "qid")

    if not ip or not qid:
        return ""

    return f"{ip}|{qid}"

def today():
    return datetime.now().strftime("%Y-%m-%d")


def mark_active(state: dict, key: str, sdp_id: Optional[str] = None):
    entry = state.get(key, {})

    count = entry.get("ticket_created_count", 0) + (1 if sdp_id else 0)

    new_entry = {
        "status": "ACTIVE",
        "last_seen": today(),
        "ticket_created_count": count,
        "last_ticket_created": entry.get("last_ticket_created") or datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }
    
    # Store or preserve sdp_id
    current_id = sdp_id or entry.get("sdp_id")
    if current_id:
        new_entry["sdp_id"] = str(current_id)
        
    state[key] = new_entry

def mark_fixed(state: dict, key: str):
    entry = state.get(key, {})

    new_entry = {
        "status": "FIXED",
        "last_seen": today(),
        "ticket_created_count": entry.get("ticket_created_count", 0),
        "last_ticket_created": entry.get("last_ticket_created")
    }
    
    # Preserve sdp_id during fixed state
    if "sdp_id" in entry:
        new_entry["sdp_id"] = entry["sdp_id"]
        
    state[key] = new_entry

def sync_state_with_qualys(state: dict, csv_path: str, delim: str):
    active_keys_in_qualys = set()

    with open(csv_path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f, delimiter=delim)
        for row in reader:
            if is_active(row):
                key = identity_key(row)
                if key:
                    active_keys_in_qualys.add(key)

    # Mark previously ACTIVE vulns as FIXED if not seen today
    for key, meta in list(state.items()):
        if meta["status"] == "ACTIVE" and key not in active_keys_in_qualys:
            mark_fixed(state, key)


def detect_delimiter(sample_line: str) -> str:
    return "\t" if "\t" in sample_line else ","

# ------------------------------
# Runner
# ------------------------------
def run(
    csv_path: str, domain: str, portal: str, token: str,
    rate: float, dry_run: bool, stop_on_error: bool, statefile: str,
    requester_email: Optional[str] = None,
    map_category_from_os: bool = False,
    static_category: Optional[str] = None,
    static_subcategory: Optional[str] = None,
    static_item: Optional[str] = None,
    add_ip_as_asset: bool = False,
    asset_id_column: Optional[str] = None,
    udf_qid_name: Optional[str] = None,
    udf_ip_name: Optional[str] = None,
    udf_run_num_name: Optional[str] = None,
    limit: Optional[int] = None,
    urgency_name: Optional[str] = None,
    no_urgency: bool = False,
    priority_name: Optional[str] = None,
    no_priority: bool = False,
    level_name: Optional[str] = None,
    no_level: bool = False,
    routing_rules_path: Optional[str] = None,
    close_fixed: Optional[str] = None
):
    base_url = f"{domain.rstrip('/')}/app/{portal}/api/v3/requests"

    # NEW: Handle Auto-Close before processing new tickets
    if close_fixed:
        close_fixed_tickets(close_fixed, base_url, token, statefile, rate)

    # Load routing rules
    global ROUTING_RULES
    ROUTING_RULES = load_routing_rules(routing_rules_path)
    if ROUTING_RULES:
        print(f"[INFO] Routing rules loaded from: {routing_rules_path}")
    else:
        print("[INFO] No routing rules file — using built-in defaults")

    # Detect delimiter
    with open(csv_path, "r", encoding="utf-8") as f:
        first_line = f.readline()
    delim = detect_delimiter(first_line)
    print(f"Detected delimiter: {'TAB' if delim=='\\t' else 'COMMA'}")
    print(f"Endpoint: {base_url}")

    # ================= STATE HANDLING =================
    state = load_state(statefile)
    global STATE_REF
    STATE_REF = state

    if statefile:
        state_dir = os.path.dirname(statefile) or "."
        os.makedirs(state_dir, exist_ok=True)

    # Sync state with current Qualys Master DB
    sync_state_with_qualys(state, csv_path, delim)

    run_counter = 0
    created: int = 0
    updated: int = 0
    skipped: int = 0
    failed: int = 0
    try:
        with open(csv_path, newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f, delimiter=delim)

            for row_num, row in enumerate(reader, start=1):
                if isinstance(limit, int) and row_num > limit:
                    break

                key = identity_key(row)
                if not key:
                    skipped += 1  # type: ignore[operator]
                    print(f"[Row {row_num}] Skip row with empty KEY")
                    continue

                state_entry = state.get(key)

                vuln_status = str(row.get("Vuln Status", "Active")).strip()
                
                # Case 4: Marked as FIXED in report
                if vuln_status == "Fixed":
                    print(f"[Row {row_num}] Vulnerability {key} marked FIXED in report")
                    sdp_id = state_entry.get("sdp_id") if state_entry else None
                    if sdp_id and not dry_run:
                        # Redundant closure check (also handled by close_fixed_tickets)
                        print(f"  [CLOSE] Attempting to close ticket {sdp_id} for {key}...", end=" ", flush=True)
                        resp = close_ticket(base_url, token, sdp_id)
                        if resp.status_code in (200, 201):
                            print(" - Closed")
                        else:
                            print(f"FAILED: {resp.text[:100]}")
                    
                    mark_fixed(state, key)
                    continue

                # SELF-HEALING / DEDUPLICATION: Check ServiceDesk for existing ticket
                sdp_id_found = ticket_exists(base_url, token, key)
                
                # Case 1: Already ACTIVE in state
                if state_entry and state_entry["status"] == "ACTIVE" and not dry_run:
                    skipped += 1
                    # If state is missing the ID but we found it in SDP, update state
                    if sdp_id_found and "sdp_id" not in state_entry:
                        print(f"[Row {row_num}] Capturing missing SDP ID: {sdp_id_found} for {key}")
                        mark_active(state, key, sdp_id=sdp_id_found)
                    else:
                        count = state_entry.get("ticket_created_count", 0)
                        print(f"[Row {row_num}] Skip ACTIVE duplicate {key} (Tickets so far: {count})")
                    continue
                
                # Case 2: Found in SDP but not ACTIVE in state (e.g. state lost or marked FIXED incorrectly)
                if not dry_run and sdp_id_found and (not state_entry or state_entry.get("status") != "FIXED"):
                    skipped += 1
                    print(f"[Row {row_num}] Found existing SDP ID: {sdp_id_found} for {key} (Syncing State)")
                    mark_active(state, key, sdp_id=sdp_id_found)
                    continue

                # Case 3: Previously FIXED → allow reopen and update via PUT
                if state_entry and state_entry.get("status") == "FIXED":
                    # Increment ticket count in state
                    new_count = state_entry.get("ticket_created_count", 0) + 1
                    state_entry["ticket_created_count"] = new_count
                    
                    # Compute the new subject with updated count
                    new_subj = subject(row, key, state)
                    
                    old_sdp_id = state_entry.get("sdp_id")
                    if old_sdp_id and not dry_run:
                        # Call SDP to reopen the ticket
                        print(f"[Row {row_num}] Reopening ticket {old_sdp_id} for vulnerability {key} (TC#: {new_count})")
                        try:
                            r = reopen_ticket(base_url, token, old_sdp_id, new_subj)
                            if r.status_code == 200:
                                updated += 1  # type: ignore[operator]
                                print(f"  [Reopen Success] Updated Subject to: {new_subj}")
                                mark_active(state, key)
                            else:
                                failed += 1  # type: ignore[operator]
                                print(f"  [Reopen Failed] Status {r.status_code}: {r.text}", file=sys.stderr)
                        except Exception as e:
                            failed += 1  # type: ignore[operator]
                            print(f"  [Reopen Error] {e}", file=sys.stderr)
                    else:
                        print(f"[Row {row_num}] Marking {key} as ACTIVE again (No SDP ID found to reopen)")
                        mark_active(state, key)
                    
                    # Very important: continue to the next row so we don't accidentally create a duplicate new ticket!
                    continue



                run_counter += 1  # type: ignore[operator]

                try:
                    payload = build_payload(
                        row, run_counter, requester_email,
                        map_category_from_os,
                        static_category, static_subcategory, static_item,
                        add_ip_as_asset, asset_id_column,
                        udf_qid_name, udf_ip_name, udf_run_num_name,
                        get_assigned_technician(get_rr_state_path(statefile)),
                        urgency_name, no_urgency,
                        priority_name, no_priority,
                        level_name, no_level
                    )
                except Exception as e:
                    failed += 1  # type: ignore[operator]
                    print(f"[Row {row_num}] Build error: {e}", file=sys.stderr)
                    if stop_on_error:
                        break
                    continue

                if dry_run:
                    print(f"[Row {row_num}] DRY-RUN payload created")
                    created += 1  # type: ignore[operator]
                    continue

                resp = post_sdp(base_url, token, payload)

                if resp.status_code in (200, 201, 202):
                    created += 1  # type: ignore[operator]
                    
                    # Extract SDP Request ID from response
                    sdp_id = None
                    try:
                        res_json = resp.json()
                        sdp_id = res_json.get("request", {}).get("id")
                    except:
                        pass
                        
                    mark_active(state, key, sdp_id=sdp_id)

                    count = state[key].get("ticket_created_count", 1)
                    print(f"[Row {row_num}] Created OK {key} (SDP ID: {sdp_id})")

                else:
                    failed += 1  # type: ignore[operator]
                    print(f"[Row {row_num}] Failed Error {resp.text[:500]}", file=sys.stderr)
                    if stop_on_error:
                        break

                time.sleep(rate)

    except KeyboardInterrupt:
        print("\n⚠️ Interrupted by user (Ctrl+C). Saving state...")

    finally:
        save_state(statefile, state)
        print("\n=== FINAL SUMMARY ===")
        print(f"Created : {created}")
        print(f"Skipped : {skipped}")
        print(f"Failed  : {failed}")
        if statefile:
            print(f"State saved to: {statefile}")



# ------------------------------
# CLI
# ------------------------------
if __name__ == "__main__":
    ap = argparse.ArgumentParser(
        description="Create ManageEngine SDP requests from Qualys CSV/TSV (beautiful HTML; safe picklists)."
    )
    ap.add_argument("--csv", required=True, help="Path to Qualys Master DB CSV/TSV")
    ap.add_argument("--domain", required=True, help="SDP base, e.g., https://sdpondemand.manageengine.in")
    ap.add_argument("--portal", required=True, help="Portal, e.g., itdesk")
    ap.add_argument("--token", required=True, help="Zoho OAuth access token (Zoho-oauthtoken)")
    ap.add_argument("--rate", type=float, default=0.5, help="Seconds between requests")
    ap.add_argument("--dry-run", action="store_true", help="Build payloads without POST")
    ap.add_argument("--stop-on-error", action="store_true", help="Stop at first failure")
    ap.add_argument("--statefile", default="Qualys/State/sdp_qualys_state.json", help="Dedup state JSON path")


    # Optional fields
    ap.add_argument("--requester-email", default=SDP_REQUESTER_EMAIL,
                    help="Requester email; omit to let SDP default to OAuth user")
    ap.add_argument("--map-category-from-os", action="store_true",
                    help="Derive Category/Subcategory/Item from OS via mapping (ensure these names exist in SDP)")
    ap.add_argument("--category", help="Static Category name")
    ap.add_argument("--subcategory", help="Static Subcategory name")
    ap.add_argument("--item", help="Static Item name")

    # Assets options
    ap.add_argument("--add-ip-as-asset", action="store_true",
                    help="Associate IP as an SDP asset by name (use only if such assets exist in SDP)")
    ap.add_argument("--asset-id-column",
                    help="CSV header that contains SDP Asset ID; if set, assets are added by ID")

    # UDF options (only if you know the exact API names in your template)
    ap.add_argument("--udf-qid-name", help="UDF API name for storing QID")
    ap.add_argument("--udf-ip-name", help="UDF API name for storing IP")
    ap.add_argument("--udf-run-num-name", help="UDF API name for storing run number (numeric UDF)")

    # Control
    ap.add_argument("--limit", type=int, help="Process only first N rows")

    # Picklist override/omit options
    ap.add_argument("--urgency-name", help="Set urgency name explicitly; omit to derive from severity")
    ap.add_argument("--no-urgency", action="store_true", help="Do not send 'urgency' field")
    ap.add_argument("--priority-name", help="Set priority name explicitly; omit to derive from severity")
    ap.add_argument("--no-priority", action="store_true", help="Do not send 'priority' field")
    ap.add_argument("--level-name", help="Set level name explicitly; omit to derive from severity")
    ap.add_argument("--no-level", action="store_true", help="Do not send 'level' field")

    ap.add_argument("--routing-rules",
                    default=os.path.join("Config", "routing_rules.json"),
                    help="Path to routing_rules.json for dynamic category/email routing")
    ap.add_argument("--close-fixed", help="Path to CSV containing fixed vulns to close in SDP")

    args = ap.parse_args()

    run(
        args.csv, args.domain, args.portal, args.token,
        args.rate, args.dry_run, args.stop_on_error, args.statefile,
        args.requester_email, args.map_category_from_os,
        args.category, args.subcategory, args.item,
        args.add_ip_as_asset, args.asset_id_column,
        args.udf_qid_name, args.udf_ip_name, args.udf_run_num_name,
        args.limit,
        args.urgency_name, args.no_urgency,
        args.priority_name, args.no_priority,
        args.level_name, args.no_level,
        routing_rules_path=args.routing_rules,
        close_fixed=args.close_fixed
    )
