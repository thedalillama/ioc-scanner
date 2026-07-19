import argparse
import html
import json
import re
import sqlite3
import subprocess
import sys
import threading
import urllib.parse
import webbrowser
import getpass
import platform
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional


TASK_NAMES = [
    "Codex Threat Feed Import",
    "Codex IOC Daily Scan",
    "Codex Host Tripwire",
    "Codex Threat RSS Monitor",
    "Codex Alert Notifier",
]

TRIPWIRE_BASELINE_TASK_NAME = "Codex Host Tripwire Baseline (System)"


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def parse_display_datetime(value: Any) -> Optional[datetime]:
    if value in (None, ""):
        return None
    text = str(value).strip()
    if not text:
        return None
    candidates = [normalize_iso_candidate(text)]
    if text.endswith("Z"):
        candidates.append(normalize_iso_candidate(text.replace("Z", "+00:00")))
    for candidate in candidates:
        try:
            dt = datetime.fromisoformat(candidate)
            if dt.tzinfo is not None:
                dt = dt.astimezone()
            return dt
        except ValueError:
            continue
    return None


def format_local_date_label(dt: datetime) -> str:
    today = datetime.now().astimezone().date()
    target = dt.date()
    delta_days = (target - today).days
    if delta_days == 0:
        return "Today"
    if delta_days == -1:
        return "Yesterday"
    if delta_days == 1:
        return "Tomorrow"
    if target.year == today.year:
        return dt.strftime("%b %d").replace(" 0", " ")
    return dt.strftime("%b %d, %Y").replace(" 0", " ")


def format_local_time_label(dt: datetime, include_tenths: bool = False) -> str:
    base = dt.strftime("%I:%M:%S %p").lstrip("0")
    if include_tenths:
        tenths = int(dt.microsecond / 100000)
        parts = base.split(" ")
        return f"{parts[0]}.{tenths} {parts[1]}"
    return base


def pretty_time(value: Any) -> str:
    if value in (None, ""):
        return "—"
    dt = parse_display_datetime(value)
    if dt is not None:
        return f"{format_local_date_label(dt)} at {format_local_time_label(dt)}"
    text = str(value).strip()
    return text or "—"

def normalize_iso_candidate(text: str) -> str:
    match = re.match(r"^(?P<prefix>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(?P<fraction>\d+))?(?P<suffix>Z|[+-]\d{2}:\d{2})?$", text)
    if not match:
        return text
    prefix = match.group("prefix")
    fraction = match.group("fraction") or ""
    suffix = match.group("suffix") or ""
    if fraction:
        fraction = (fraction[:6]).ljust(6, "0")
        return f"{prefix}.{fraction}{suffix}"
    return f"{prefix}{suffix}"


def render_metric_time_value(value: Any) -> str:
    if value in (None, ""):
        return esc("-")
    dt = parse_display_datetime(value)
    if dt is not None:
        return (
            f'{esc(format_local_date_label(dt))}'
            f'<span class="metric-time-sub">{esc(format_local_time_label(dt, include_tenths=True))}</span>'
        )
    text = str(value).strip()
    if not text:
        return esc("-")
    return esc(text)

def classify_task_result(task: Dict[str, Any]) -> Dict[str, str]:
    raw_result = task.get("LastTaskResult")
    state = str(task.get("State") or "").strip()
    installed = bool(task.get("Installed"))
    enabled = task.get("Enabled")

    if not installed:
        return {
            "label": "Missing",
            "tone": "high",
            "message": "Scheduled task is not installed.",
            "raw": "",
        }

    if enabled is False:
        return {
            "label": "Disabled",
            "tone": "medium",
            "message": "Scheduled task is installed but disabled.",
            "raw": str(raw_result or ""),
        }

    raw_text = "" if raw_result in (None, "") else str(raw_result).strip()
    try:
        raw_value = int(raw_text) if raw_text else None
    except ValueError:
        raw_value = None

    if raw_value == 0:
        return {
            "label": "Healthy",
            "tone": "ok",
            "message": "Last run completed successfully.",
            "raw": raw_text,
        }

    if raw_value == 267009:
        return {
            "label": "Running",
            "tone": "info",
            "message": "Task is currently running.",
            "raw": raw_text,
        }

    if raw_value == 267010:
        return {
            "label": "Queued",
            "tone": "info",
            "message": "Task is queued and waiting for the next available run slot.",
            "raw": raw_text,
        }

    if raw_value == 267011:
        return {
            "label": "Waiting",
            "tone": "info",
            "message": "Task has not run yet.",
            "raw": raw_text,
        }

    if state.lower() == "running":
        return {
            "label": "Running",
            "tone": "info",
            "message": "Task is currently running.",
            "raw": raw_text,
        }

    if raw_text:
        return {
            "label": "Needs Attention",
            "tone": "medium",
            "message": "Last run returned a non-success code. Review the raw result and task output.",
            "raw": raw_text,
        }

    return {
        "label": "Unknown",
        "tone": "medium",
        "message": "Task state is available but the last result is not populated.",
        "raw": raw_text,
    }


def parse_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8-sig") as handle:
        return json.load(handle)


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def html_page(title: str, body: str) -> str:
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{html.escape(title)}</title>
  <style>
    :root {{ color-scheme: light; --bg:#f6f2ea; --panel:#fffdfa; --panel-soft:#f4ede4; --ink:#22323b; --muted:#6b7a81; --line:rgba(34,50,59,.12); --sage:#7da38f; --sage-soft:#e8f0ea; --blue:#87a9c2; --blue-soft:#e8eff5; --amber:#d8ab63; --amber-soft:#fbf1df; --rose:#bb7b72; --rose-soft:#f6e7e3; --shadow:0 18px 42px rgba(74,82,88,.10); }}
    * {{ box-sizing:border-box; }} html {{ background:#f8f4ee; }} body {{ margin:0; min-height:100vh; color:var(--ink); background:radial-gradient(circle at top left, rgba(125,163,143,.14), transparent 25%),radial-gradient(circle at top right, rgba(135,169,194,.16), transparent 28%),linear-gradient(180deg,#faf7f1 0%,#f2ece3 100%); font:15px/1.65 "Segoe UI Variable Text","Aptos","Segoe UI",sans-serif; }}
    a {{ color:#4f6c7e; text-decoration:none; }} a:hover {{ color:#2f4957; }}
    .shell {{ max-width:1440px; margin:0 auto; padding:28px 22px 56px; }} .page-stack > * + * {{ margin-top:22px; }}
    .panel {{ background:var(--panel); border:1px solid var(--line); border-radius:24px; box-shadow:var(--shadow); padding:24px; }} .panel.soft {{ background:rgba(255,255,255,.65); }}
    .hero {{ display:grid; gap:18px; grid-template-columns:minmax(0,2fr) minmax(320px,.95fr); align-items:stretch; }} .hero-main {{ position:relative; overflow:hidden; border-radius:30px; padding:34px; min-height:280px; --mood-glow: rgba(125,163,143,.22); --mood-wash: rgba(255,248,240,.92); --mood-image:none; background:linear-gradient(180deg,rgba(255,255,255,.75),var(--mood-wash)),radial-gradient(circle at 75% 22%, var(--mood-glow), transparent 24%),radial-gradient(circle at 15% 82%, rgba(135,169,194,.18), transparent 26%),linear-gradient(135deg,#fcfbf8 0%,#f2ece2 100%); border:1px solid rgba(34,50,59,.10); box-shadow:0 26px 60px rgba(93,102,108,.12); }}
    .hero-main.mood-steady {{ --mood-glow: rgba(125,163,143,.24); --mood-wash: rgba(244,250,245,.92); }}
    .hero-main.mood-needs_review {{ --mood-glow: rgba(216,171,99,.24); --mood-wash: rgba(255,249,239,.94); }}
    .hero-main.mood-action_needed {{ --mood-glow: rgba(187,123,114,.24); --mood-wash: rgba(253,244,242,.94); }}
    .hero-main::before {{ content:""; position:absolute; inset:0; pointer-events:none; background-image:var(--mood-image); background-size:cover; background-position:center; opacity:.08; }}
    .page-topbar {{ display:flex; align-items:center; justify-content:space-between; gap:16px; margin-bottom:14px; }} .brand-mark {{ display:inline-flex; align-items:center; gap:10px; font-size:13px; color:var(--muted); text-transform:uppercase; letter-spacing:.16em; font-weight:700; }} .brand-dot {{ width:12px; height:12px; border-radius:999px; background:linear-gradient(135deg,#9ec0ab,#83a9c8); box-shadow:0 0 0 6px rgba(125,163,143,.10); }}
    .kicker {{ text-transform:uppercase; letter-spacing:.14em; color:#698576; font-size:11px; margin-bottom:12px; font-weight:700; }} h1,h2,h3 {{ margin:0; letter-spacing:-.03em; color:var(--ink); }} h1 {{ font-size:46px; line-height:1.02; max-width:12ch; margin-bottom:14px; font-weight:650; }} h2 {{ font-size:24px; margin-bottom:14px; font-weight:620; }} h3 {{ font-size:12px; text-transform:uppercase; letter-spacing:.12em; color:var(--muted); margin-bottom:12px; font-weight:700; }} .lede {{ margin:0; max-width:64ch; font-size:16px; color:#5f6e76; }}
    .hero-actions,.task-actions,.subnav {{ display:flex; gap:10px; align-items:center; flex-wrap:wrap; }} .hero-actions {{ margin-top:24px; }} .hero-meta {{ display:flex; gap:10px; flex-wrap:wrap; margin-top:18px; color:var(--muted); font-size:13px; }}
    .grid {{ display:grid; gap:18px; }} .grid.two {{ grid-template-columns:repeat(2,minmax(0,1fr)); }} .grid.three {{ grid-template-columns:repeat(3,minmax(0,1fr)); }} .stack > * + * {{ margin-top:14px; }} .cards {{ display:grid; gap:14px; grid-template-columns:repeat(auto-fit,minmax(180px,1fr)); }}
    .metric,.focus-card,.care-tile,.task,.activity-item,.mood-chip {{ background:rgba(255,255,255,.76); border:1px solid rgba(34,50,59,.10); border-radius:18px; }} .metric {{ padding:16px; min-height:104px; }} .metric .label,.mood-chip .label {{ color:var(--muted); font-size:11px; text-transform:uppercase; letter-spacing:.12em; font-weight:700; }} .metric .value {{ font-size:26px; font-weight:650; margin-top:7px; color:var(--ink); overflow-wrap:anywhere; }} .metric .value .metric-time-sub {{ display:block; font-size:15px; line-height:1.25; margin-top:5px; color:#607079; font-weight:500; }}
    .status-pill {{ display:inline-flex; align-items:center; gap:8px; white-space:nowrap; padding:8px 13px; border-radius:999px; font-size:12px; font-weight:700; border:1px solid transparent; }} .status-ok,.status-Healthy {{ background:var(--sage-soft); color:#4d705d; border-color:rgba(125,163,143,.35); }} .status-medium,.status-Warning {{ background:var(--amber-soft); color:#8a6735; border-color:rgba(216,171,99,.32); }} .status-high,.status-High {{ background:var(--rose-soft); color:#90564c; border-color:rgba(187,123,114,.28); }} .status-info {{ background:var(--blue-soft); color:#58758a; border-color:rgba(135,169,194,.32); }}
    .btn {{ display:inline-flex; align-items:center; justify-content:center; gap:8px; padding:10px 16px; border-radius:999px; border:1px solid rgba(34,50,59,.12); background:rgba(255,255,255,.82); color:var(--ink); font:inherit; cursor:pointer; transition:transform .14s ease, box-shadow .14s ease; }} .btn:hover {{ transform:translateY(-1px); box-shadow:0 12px 24px rgba(80,88,94,.10); }} .btn.primary {{ background:linear-gradient(135deg,#8eb39d,#86a9c2); color:#fff; border-color:transparent; font-weight:700; }} .btn.active {{ background:#eef3ee; border-color:rgba(125,163,143,.28); }}
    .mini,.focus-meta,.task-meta {{ color:var(--muted); font-size:13px; }} .flash {{ padding:13px 15px; border-radius:16px; border:1px solid rgba(135,169,194,.22); background:rgba(232,239,245,.9); color:#536b7d; }}
    .focus-card {{ padding:18px; }} .focus-card.calm,.care-tile.good {{ background:linear-gradient(180deg,rgba(232,240,234,.92),rgba(255,255,255,.84)); }} .focus-card.warning,.care-tile.care {{ background:linear-gradient(180deg,rgba(251,241,223,.94),rgba(255,255,255,.84)); }} .focus-card.critical,.care-tile.serious {{ background:linear-gradient(180deg,rgba(246,231,227,.95),rgba(255,255,255,.84)); }} .focus-card.report {{ background:linear-gradient(180deg,rgba(232,239,245,.92),rgba(255,255,255,.84)); }} .focus-label {{ color:#698576; text-transform:uppercase; letter-spacing:.12em; font-size:11px; font-weight:700; margin-bottom:8px; }} .focus-title {{ font-size:24px; font-weight:630; margin-bottom:6px; }} .focus-copy {{ color:#475861; margin-bottom:8px; }}
    .care-list,.activity-list {{ display:grid; gap:12px; }} .care-tile {{ padding:16px 18px; }} .care-tile h4 {{ margin:0 0 6px; font-size:17px; font-weight:620; }} .care-tile p {{ margin:0; color:#54636b; }} .activity-item {{ display:grid; gap:4px; padding:14px 16px; }}
    .task {{ padding:18px; }} .task + .task {{ margin-top:14px; }} .task-head {{ display:flex; align-items:flex-start; justify-content:space-between; gap:14px; margin-bottom:14px; }} .task-name {{ font-size:19px; font-weight:630; margin-bottom:4px; }}
    .task-detail {{ margin-top:14px; border-top:1px solid rgba(34,50,59,.10); padding-top:14px; }} .task-detail summary, details.panel > summary, .inline-detail summary {{ cursor:pointer; list-style:none; color:#44545d; font-weight:600; }} .task-detail summary::-webkit-details-marker, details.panel > summary::-webkit-details-marker, .inline-detail summary::-webkit-details-marker {{ display:none; }}
    .kv {{ display:grid; grid-template-columns:170px 1fr; gap:8px 14px; font-size:14px; padding:12px 0 2px; }} .kv dt {{ color:var(--muted); font-weight:600; }} .kv dd {{ margin:0; color:var(--ink); overflow-wrap:anywhere; }}
    table {{ width:100%; border-collapse:collapse; font-size:14px; }} thead th {{ color:var(--muted); font-weight:700; text-transform:uppercase; letter-spacing:.08em; font-size:11px; padding-top:0; }} th,td {{ padding:11px 8px; border-bottom:1px solid rgba(34,50,59,.08); vertical-align:top; text-align:left; overflow-wrap:anywhere; }} tbody tr:hover td {{ background:rgba(255,255,255,.42); }}
    .finding {{ padding:12px 14px; border-radius:16px; border:1px solid rgba(34,50,59,.10); background:rgba(255,255,255,.72); }} .finding.high {{ background:var(--rose-soft); }} .finding.medium {{ background:var(--amber-soft); }}
    .path,pre {{ background:#f8f5ef; border:1px solid rgba(34,50,59,.10); border-radius:16px; color:#354751; }} .path {{ font:12px/1.5 "Cascadia Code","Consolas",monospace; padding:9px 11px; }} pre {{ margin:0; padding:16px; overflow:auto; font:12px/1.55 "Cascadia Code","Consolas",monospace; }}
    .mood-strip {{ display:grid; gap:12px; grid-template-columns:repeat(auto-fit,minmax(150px,1fr)); }} .mood-chip {{ padding:14px 16px; }} .mood-chip .value {{ margin-top:6px; font-size:17px; font-weight:620; color:var(--ink); }}
    @media (max-width:1100px) {{ .hero,.grid.two,.grid.three {{ grid-template-columns:1fr; }} h1 {{ max-width:none; font-size:38px; }} }} @media (max-width:760px) {{ .shell {{ padding:18px 14px 40px; }} .panel,.hero-main {{ padding:20px; }} .task-head,.page-topbar {{ flex-direction:column; align-items:flex-start; }} .kv {{ grid-template-columns:1fr; }} }}
  </style>
</head>
<body>
  <div class="shell"><div class="page-stack">{body}</div></div>
</body>
</html>
"""


def esc(value: Any) -> str:
    return html.escape("" if value is None else str(value))



@dataclass
class AppConfig:
    settings_path: Path
    runtime_root: Path
    data_root: Path
    state_db_path: Path
    alert_inbox_path: Path
    alert_archive_path: Path
    indicator_export_path: Path
    protection_profile: str
    ui_persona: str
    repo_root: Path


DEFAULT_PERSONA_PROFILES = {
    "user": {
        "persona_id": "user",
        "display_name": "Home User",
        "description": "Simple local-PC view for an everyday PC owner who wants clear guidance without deep technical detail.",
        "default_skin": "light_care",
        "report_language": "simple",
        "show_csf_codes": False,
        "show_raw_evidence": False,
        "show_diagnostics": False,
        "show_reports": False,
        "show_evidence_links": False,
        "visible_routes": ["/", "/govern", "/identify", "/protect", "/detect", "/respond", "/recover"],
        "hidden_routes": ["/reports", "/diagnostics", "/detect/evidence-snapshot"],
        "automation_level": "guided",
        "require_confirmation_for": ["persona_changes", "protection_profile_changes"],
    },
    "advanced_user": {
        "persona_id": "advanced_user",
        "display_name": "Advanced User",
        "description": "Richer local-PC view for an experienced user who wants evidence pages and fuller security language.",
        "default_skin": "light_care",
        "report_language": "standard",
        "show_csf_codes": True,
        "show_raw_evidence": False,
        "show_diagnostics": False,
        "show_reports": True,
        "show_evidence_links": True,
        "visible_routes": ["/", "/govern", "/identify", "/protect", "/detect", "/respond", "/recover", "/reports", "/detect/evidence-snapshot"],
        "hidden_routes": ["/diagnostics"],
        "automation_level": "review",
        "require_confirmation_for": ["persona_changes", "protection_profile_changes"],
    },
    "analyst": {
        "persona_id": "analyst",
        "display_name": "Analyst",
        "description": "Analysis-oriented local-PC view for security practitioners who want findings, posture review, evidence interpretation, threat context, and reports without full repair diagnostics by default.",
        "default_skin": "lifestyle",
        "report_language": "technical",
        "show_csf_codes": True,
        "show_raw_evidence": True,
        "show_diagnostics": False,
        "show_reports": True,
        "show_evidence_links": True,
        "visible_routes": ["/", "/govern", "/identify", "/protect", "/detect", "/respond", "/recover", "/reports", "/detect/evidence-snapshot"],
        "hidden_routes": ["/diagnostics"],
        "automation_level": "analysis",
        "require_confirmation_for": ["persona_changes", "protection_profile_changes"],
    },
    "csf_native": {
        "persona_id": "csf_native",
        "display_name": "NIST CSF Native",
        "description": "Framework-oriented local-PC view for people who want to operate the app through formal NIST CSF terminology and evidence-backed status.",
        "default_skin": "lifestyle",
        "report_language": "standard",
        "show_csf_codes": True,
        "show_raw_evidence": False,
        "show_diagnostics": False,
        "show_reports": True,
        "show_evidence_links": True,
        "visible_routes": ["/", "/govern", "/identify", "/protect", "/detect", "/respond", "/recover", "/reports", "/detect/evidence-snapshot"],
        "hidden_routes": ["/diagnostics"],
        "automation_level": "framework",
        "require_confirmation_for": ["persona_changes", "protection_profile_changes"],
    },
    "tech": {
        "persona_id": "tech",
        "display_name": "Technician",
        "description": "Technical local-PC view for hands-on operators who need reports, diagnostics, raw evidence context, and troubleshooting detail.",
        "default_skin": "lifestyle",
        "report_language": "technical",
        "show_csf_codes": True,
        "show_raw_evidence": True,
        "show_diagnostics": True,
        "show_reports": True,
        "show_evidence_links": True,
        "visible_routes": ["/", "/govern", "/identify", "/protect", "/detect", "/respond", "/recover", "/reports", "/diagnostics", "/detect/evidence-snapshot"],
        "hidden_routes": [],
        "automation_level": "operator",
        "require_confirmation_for": ["persona_changes", "protection_profile_changes"],
    },
}

DEFAULT_SYSTEM_PROFILES = {
    "windows_home": {
        "system_profile_id": "windows_home",
        "display_name": "Windows Home",
        "supported": True,
        "enterprise_managed": False,
        "expected_controls": [
            "defender",
            "firewall",
            "windows_update",
            "family_safety",
            "standard_user_accounts",
            "controlled_folder_access",
            "smart_app_control",
        ],
        "unsupported_or_limited_controls": [
            "local_group_policy",
            "applocker",
            "wdac_advanced_policy",
            "domain_join",
        ],
        "advanced_controls_available": [],
    },
    "windows_pro": {
        "system_profile_id": "windows_pro",
        "display_name": "Windows Pro",
        "supported": True,
        "enterprise_managed": False,
        "expected_controls": [
            "defender",
            "firewall",
            "windows_update",
            "bitlocker",
            "remote_desktop",
            "local_security_policy",
            "local_group_policy",
            "controlled_folder_access",
            "smart_app_control",
        ],
        "unsupported_or_limited_controls": [],
        "advanced_controls_available": [
            "advanced_firewall_rules",
            "applocker_possible",
            "wdac_possible",
        ],
    },
    "enterprise_managed": {
        "system_profile_id": "enterprise_managed",
        "display_name": "Enterprise managed",
        "supported": False,
        "enterprise_managed": True,
        "expected_controls": [],
        "unsupported_or_limited_controls": [],
        "advanced_controls_available": [],
        "message": "This PC appears to be managed by an organization. Some settings may be controlled by IT policy.",
    },
}



def profile_catalog_paths(repo_root: Path) -> Dict[str, Path]:
    profile_root = repo_root / "profiles"
    return {
        "root": profile_root,
        "persona": profile_root / "persona-profiles.json",
        "system": profile_root / "system-profiles.json",
    }


def normalize_persona_profile(persona_id: str, payload: Dict[str, Any], fallback: Dict[str, Any]) -> Dict[str, Any]:
    profile = dict(fallback)
    profile.update(payload or {})
    profile["persona_id"] = str(profile.get("persona_id") or persona_id).strip().lower() or persona_id
    profile["display_name"] = str(profile.get("display_name") or fallback.get("display_name") or persona_id.title())
    profile["description"] = str(profile.get("description") or fallback.get("description") or "")
    profile["default_skin"] = str(profile.get("default_skin") or fallback.get("default_skin") or "light_care")
    profile["report_language"] = str(profile.get("report_language") or fallback.get("report_language") or "simple")
    for key in ("show_csf_codes", "show_raw_evidence", "show_diagnostics", "show_reports", "show_evidence_links"):
        profile[key] = bool(profile.get(key))
    profile["visible_routes"] = [str(route) for route in (profile.get("visible_routes") or fallback.get("visible_routes") or [])]
    profile["hidden_routes"] = [str(route) for route in (profile.get("hidden_routes") or fallback.get("hidden_routes") or [])]
    profile["automation_level"] = str(profile.get("automation_level") or fallback.get("automation_level") or "guided")
    profile["require_confirmation_for"] = [str(item) for item in (profile.get("require_confirmation_for") or fallback.get("require_confirmation_for") or [])]
    return profile


def normalize_system_profile(profile_id: str, payload: Dict[str, Any], fallback: Dict[str, Any]) -> Dict[str, Any]:
    profile = dict(fallback)
    profile.update(payload or {})
    profile["system_profile_id"] = str(profile.get("system_profile_id") or profile_id).strip().lower() or profile_id
    profile["display_name"] = str(profile.get("display_name") or fallback.get("display_name") or profile_id.replace("_", " ").title())
    profile["supported"] = bool(profile.get("supported", fallback.get("supported", True)))
    profile["enterprise_managed"] = bool(profile.get("enterprise_managed", fallback.get("enterprise_managed", False)))
    for key in ("expected_controls", "unsupported_or_limited_controls", "advanced_controls_available"):
        profile[key] = [str(item) for item in (profile.get(key) or fallback.get(key) or [])]
    if "message" in profile or "message" in fallback:
        profile["message"] = str(profile.get("message") or fallback.get("message") or "")
    return profile


def load_profile_catalog(path: Path, fallback: Dict[str, Dict[str, Any]], catalog_key: str, normalizer) -> Dict[str, Dict[str, Any]]:
    catalog = {key: normalizer(key, value, fallback[key]) for key, value in fallback.items()}
    if not path.exists():
        return catalog
    try:
        payload = parse_json(path)
    except Exception:
        return catalog
    rows = payload.get(catalog_key) if isinstance(payload, dict) else None
    if not isinstance(rows, list):
        return catalog
    for row in rows:
        if not isinstance(row, dict):
            continue
        profile_id = str(row.get("persona_id") or row.get("system_profile_id") or "").strip().lower()
        if not profile_id:
            continue
        fallback_row = fallback.get(profile_id, {})
        catalog[profile_id] = normalizer(profile_id, row, fallback_row)
    return catalog


def load_persona_profiles(repo_root: Path) -> Dict[str, Dict[str, Any]]:
    return load_profile_catalog(profile_catalog_paths(repo_root)["persona"], DEFAULT_PERSONA_PROFILES, "personas", normalize_persona_profile)


def load_system_profiles(repo_root: Path) -> Dict[str, Dict[str, Any]]:
    return load_profile_catalog(profile_catalog_paths(repo_root)["system"], DEFAULT_SYSTEM_PROFILES, "system_profiles", normalize_system_profile)


def get_effective_persona(config: AppConfig, persona_profiles: Optional[Dict[str, Dict[str, Any]]] = None) -> Dict[str, Any]:
    catalog = persona_profiles or load_persona_profiles(config.repo_root)
    persona_id = str(config.ui_persona or "user").strip().lower() or "user"
    return dict(catalog.get(persona_id) or catalog.get("user") or normalize_persona_profile("user", {}, DEFAULT_PERSONA_PROFILES["user"]))


def get_effective_system_profile(status: Dict[str, Any], system_profiles: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    local_pc = get_local_pc_facts(status)
    edition = str(local_pc.get("WindowsEdition") or "").lower()
    profile_id = "windows_home"
    if "enterprise" in edition or "education" in edition:
        profile_id = "enterprise_managed"
    elif "pro" in edition:
        profile_id = "windows_pro"
    profile = dict(system_profiles.get(profile_id) or system_profiles.get("windows_home") or DEFAULT_SYSTEM_PROFILES["windows_home"])
    profile["detected_from_windows_edition"] = local_pc.get("WindowsEdition") or "Unknown"
    return profile


def persona_allows_route(persona_profile: Dict[str, Any], route: str) -> bool:
    route = str(route or "/")
    hidden_routes = set(persona_profile.get("hidden_routes") or [])
    if route in hidden_routes:
        return False
    visible_routes = set(persona_profile.get("visible_routes") or [])
    if visible_routes:
        return route in visible_routes
    return True


def persona_show_reports(persona_profile: Dict[str, Any]) -> bool:
    return bool((persona_profile or {}).get("show_reports"))


def persona_show_diagnostics(persona_profile: Dict[str, Any]) -> bool:
    return bool((persona_profile or {}).get("show_diagnostics"))


def persona_show_csf_codes(persona_profile: Dict[str, Any]) -> bool:
    return bool((persona_profile or {}).get("show_csf_codes"))


def persona_show_evidence_links(persona_profile: Dict[str, Any]) -> bool:
    return bool((persona_profile or {}).get("show_evidence_links"))


def simplify_for_persona(persona_profile: Dict[str, Any], technical_text: str, plain_text: str) -> str:
    return plain_text if str((persona_profile or {}).get("report_language") or "simple") == "simple" else technical_text


def resolve_settings_path(settings_dir: Path, raw_value: object, default_value: Path) -> Path:
    if raw_value is None or str(raw_value).strip() == "":
        return default_value.resolve()
    configured = Path(str(raw_value))
    if not configured.is_absolute():
        configured = settings_dir / configured
    return configured.resolve()


def load_settings(settings_path: Path) -> AppConfig:
    repo_root = Path(__file__).resolve().parent
    settings = {}
    if settings_path.exists():
        settings = parse_json(settings_path)

    settings_dir = settings_path.resolve().parent
    runtime_root = resolve_settings_path(settings_dir, settings.get("RuntimeRoot"), settings_dir)
    data_root = resolve_settings_path(settings_dir, settings.get("DataRoot"), runtime_root)
    state_db_path = resolve_settings_path(settings_dir, settings.get("StateDbPath"), data_root / "state" / "ioc-store.db")
    alert_inbox_path = resolve_settings_path(settings_dir, settings.get("AlertInboxPath") or settings.get("AlertWatchPath"), data_root / "alerts" / "pending")
    alert_archive_path = resolve_settings_path(settings_dir, settings.get("AlertArchivePath"), data_root / "alerts" / "archive")
    indicator_export_path = resolve_settings_path(settings_dir, settings.get("IndicatorExportPath"), data_root / "indicators" / "feed-indicators-latest.json")
    protection_profile = str(settings.get("ProtectionProfile") or "microsoft_baseline")
    persona_profiles = load_persona_profiles(repo_root)
    ui_persona = str(settings.get("UiPersona") or "user").strip().lower() or "user"
    if ui_persona not in persona_profiles:
        ui_persona = "user"

    return AppConfig(
        settings_path=settings_path.resolve(),
        runtime_root=runtime_root,
        data_root=data_root,
        state_db_path=state_db_path,
        alert_inbox_path=alert_inbox_path,
        alert_archive_path=alert_archive_path,
        indicator_export_path=indicator_export_path,
        protection_profile=protection_profile,
        ui_persona=ui_persona,
        repo_root=repo_root,
    )



def run_process(args: List[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, capture_output=True, text=True, check=False)


def run_powershell_json(command: str) -> Any:
    result = run_process(["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", command])
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or result.stdout.strip() or "PowerShell command failed")
    return json.loads(result.stdout)


def get_status_snapshot(config: AppConfig) -> Dict[str, Any]:
    script_path = config.runtime_root / "get-codex-monitor-status.ps1"
    args = [
        "powershell",
        "-NoProfile",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
        str(script_path),
        "-SettingsPath",
        str(config.settings_path),
        "-StateDbPath",
        str(config.state_db_path),
        "-AsJson",
    ]
    result = run_process(args)
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or result.stdout.strip() or "Status script failed")
    return json.loads(result.stdout)


def get_task_details(task_names: Iterable[str]) -> List[Dict[str, Any]]:
    task_list = "@(" + ",".join("'" + name.replace("'", "''") + "'" for name in task_names) + ")"
    command = f"""
$taskNames = {task_list}
$result = foreach ($taskName in $taskNames) {{
  $task = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
  if ($null -eq $task) {{
    [pscustomobject]@{{ Name = $taskName; Installed = $false }}
    continue
  }}
  $info = Get-ScheduledTaskInfo -TaskName $taskName -ErrorAction SilentlyContinue
  [pscustomobject]@{{
    Name = $task.TaskName
    Installed = $true
    State = [string]$task.State
    Enabled = [bool]$task.Settings.Enabled
    Author = [string]$task.Author
    Description = [string]$task.Description
    Principal = [string]$task.Principal.UserId
    RunLevel = [string]$task.Principal.RunLevel
    LastRunTime = if ($info -and $info.LastRunTime -is [datetime]) {{ $info.LastRunTime.ToString('o') }} else {{ [string]$info.LastRunTime }}
    NextRunTime = if ($info -and $info.NextRunTime -is [datetime]) {{ $info.NextRunTime.ToString('o') }} else {{ [string]$info.NextRunTime }}
    LastTaskResult = if ($info) {{ [string]([long]$info.LastTaskResult) }} else {{ $null }}
    Actions = @($task.Actions | ForEach-Object {{
      [pscustomobject]@{{
        Execute = [string]$_.Execute
        Arguments = [string]$_.Arguments
        WorkingDirectory = [string]$_.WorkingDirectory
      }}
    }})
    Triggers = @($task.Triggers | ForEach-Object {{
      [pscustomobject]@{{
        Type = $_.CimClass.CimClassName
        Enabled = [bool]$_.Enabled
        StartBoundary = [string]$_.StartBoundary
        EndBoundary = [string]$_.EndBoundary
        RepetitionInterval = [string]$_.Repetition.Interval
      }}
    }})
  }}
}}
$result | ConvertTo-Json -Depth 6
"""
    payload = run_powershell_json(command)
    if isinstance(payload, dict):
        return [payload]
    return payload or []


def merge_task_details(task_names: Iterable[str], direct_details: List[Dict[str, Any]], status_tasks: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    direct_by_name = {str(task.get("Name")): task for task in direct_details if task.get("Name")}
    status_by_name = {str(task.get("Name")): task for task in status_tasks if task.get("Name")}
    merged: List[Dict[str, Any]] = []
    for task_name in task_names:
        direct = dict(direct_by_name.get(task_name, {}))
        status = dict(status_by_name.get(task_name, {}))
        if direct.get("Installed") is False and status.get("Installed") is True:
            direct = {}
        merged.append(
            {
                "Name": task_name,
                "Installed": direct.get("Installed", status.get("Installed", False)),
                "State": direct.get("State") or status.get("State") or "",
                "Enabled": direct.get("Enabled") if direct.get("Enabled") is not None else status.get("Enabled"),
                "Author": direct.get("Author") or status.get("Author") or "",
                "Description": direct.get("Description") or status.get("Description") or "",
                "Principal": direct.get("Principal") or status.get("Principal") or "",
                "RunLevel": direct.get("RunLevel") or status.get("RunLevel") or "",
                "LastRunTime": direct.get("LastRunTime") or status.get("LastRunTime") or "",
                "NextRunTime": direct.get("NextRunTime") or status.get("NextRunTime") or "",
                "LastTaskResult": direct.get("LastTaskResult") if direct.get("LastTaskResult") is not None else status.get("LastTaskResult"),
                "Actions": direct.get("Actions") or [],
                "Triggers": direct.get("Triggers") or [],
            }
        )
    return merged


def run_task(task_name: str, config: AppConfig) -> str:
    if task_name not in TASK_NAMES:
        raise RuntimeError(f"Unknown task: {task_name}")
    result = run_process(["schtasks", "/Run", "/TN", task_name])
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or result.stdout.strip() or f"Failed to start scheduled task {task_name}")
    return result.stdout.strip() or f"Triggered scheduled task: {task_name}"


def run_tripwire_baseline(config: AppConfig) -> str:
    launcher_path = config.runtime_root / "codex-host-tripwire-baseline-ui.cmd"
    launcher_path.write_text(
        (
            "@echo off\r\n"
            f'powershell.exe -NoProfile -ExecutionPolicy Bypass -File "{config.runtime_root / "invoke-host-tripwire.ps1"}" -Mode Baseline -StateDbPath "{config.state_db_path}"\r\n'
            "exit /b %ERRORLEVEL%\r\n"
        ),
        encoding="ascii",
    )

    start_dt = (datetime.now().astimezone() + timedelta(minutes=1)).replace(second=0, microsecond=0)
    start_time = start_dt.strftime("%H:%M")
    task_command = f'wscript.exe //B //nologo "{config.runtime_root / "run-hidden.vbs"}" "{launcher_path}"'

    create_result = run_process(
        [
            "schtasks",
            "/Create",
            "/TN",
            TRIPWIRE_BASELINE_TASK_NAME,
            "/SC",
            "ONCE",
            "/ST",
            start_time,
            "/RU",
            "SYSTEM",
            "/RL",
            "HIGHEST",
            "/F",
            "/TR",
            task_command,
        ]
    )
    if create_result.returncode != 0:
        raise RuntimeError(create_result.stderr.strip() or create_result.stdout.strip() or "Failed to create SYSTEM baseline task")

    run_result = run_process(["schtasks", "/Run", "/TN", TRIPWIRE_BASELINE_TASK_NAME])
    if run_result.returncode != 0:
        raise RuntimeError(run_result.stderr.strip() or run_result.stdout.strip() or "Failed to start SYSTEM baseline task")

    return "Triggered Tripwire baseline as SYSTEM."


def set_protection_profile(config: AppConfig, profile_id: str) -> str:
    settings = {}
    if config.settings_path.exists():
        settings = parse_json(config.settings_path)
    settings["ProtectionProfile"] = profile_id
    config.settings_path.write_text(json.dumps(settings, indent=2) + "\n", encoding="utf-8")
    config.protection_profile = profile_id
    return f"Protection profile set to {profile_id}."


def set_ui_persona(config: AppConfig, persona_id: str) -> str:
    persona = str(persona_id or "").strip().lower()
    persona_profiles = load_persona_profiles(config.repo_root)
    if persona not in persona_profiles:
        raise RuntimeError("Unknown UI persona was provided.")
    settings = {}
    if config.settings_path.exists():
        settings = parse_json(config.settings_path)
    settings["UiPersona"] = persona
    config.settings_path.write_text(json.dumps(settings, indent=2) + "\n", encoding="utf-8")
    config.ui_persona = persona
    return f"UI persona set to {persona_label(coerce_persona_profile(persona))}."


def query_indicator_stats(db_path: Path) -> Dict[str, Any]:
    if not db_path.exists():
        return {"indicator_count": 0, "ingest_runs": [], "by_type": [], "by_source": [], "app_state": []}

    connection = sqlite3.connect(str(db_path))
    connection.row_factory = sqlite3.Row
    try:
        indicator_count = connection.execute("SELECT COUNT(*) AS count FROM indicators").fetchone()["count"]
        by_type = [dict(row) for row in connection.execute("SELECT type, COUNT(*) AS count FROM indicators GROUP BY type ORDER BY count DESC LIMIT 12")]
        by_source = [dict(row) for row in connection.execute("SELECT source, COUNT(*) AS count FROM indicators GROUP BY source ORDER BY count DESC LIMIT 12")]
        ingest_runs = [
            dict(row)
            for row in connection.execute(
                """
                SELECT id, started_at, completed_at, source_name, input_path, status, indicator_count, notes
                FROM ingest_runs
                ORDER BY id DESC
                LIMIT 10
                """
            )
        ]
        app_state = [
            dict(row)
            for row in connection.execute(
                "SELECT namespace, state_key, updated_at FROM app_state ORDER BY namespace, state_key"
            )
        ]
        return {
            "indicator_count": indicator_count,
            "ingest_runs": ingest_runs,
            "by_type": by_type,
            "by_source": by_source,
            "app_state": app_state,
        }
    finally:
        connection.close()


def build_alert_record(json_path: Path, bucket: str) -> Dict[str, Any]:
    payload = parse_json(json_path)
    metadata = payload.get("Metadata", {})
    summary = payload.get("Summary", {})
    md_path = json_path.with_suffix(".md")
    return {
        "name": json_path.name,
        "bucket": bucket,
        "path": str(json_path),
        "markdown_path": str(md_path) if md_path.exists() else "",
        "title": summary.get("Title") or json_path.name,
        "message": summary.get("Message") or "",
        "detail_lines": summary.get("DetailLines") or [],
        "severity": metadata.get("Severity") or "Unknown",
        "alert_type": metadata.get("AlertType") or "",
        "change_count": metadata.get("ChangeCount"),
        "collection_time": metadata.get("CollectionTimeUtc") or "",
        "source_report": metadata.get("SourceReport") or "",
        "payload": payload,
    }


def list_alert_records(directory: Path, bucket: str) -> List[Dict[str, Any]]:
    if not directory.exists():
        return []
    records = []
    for path in sorted(directory.glob("ALERT_*.json"), key=lambda item: item.stat().st_mtime, reverse=True):
        try:
            records.append(build_alert_record(path, bucket))
        except Exception as exc:
            records.append(
                {
                    "name": path.name,
                    "bucket": bucket,
                    "path": str(path),
                    "title": path.name,
                    "message": f"Unable to parse alert: {exc}",
                    "detail_lines": [],
                    "severity": "Error",
                    "alert_type": "",
                    "change_count": None,
                    "collection_time": "",
                    "source_report": "",
                    "payload": None,
                }
            )
    return records


def list_recent_reports(runtime_root: Path) -> List[Dict[str, Any]]:
    patterns = ["HOST_IOC_*.json", "HOST_TRIPWIRE_*.json", "THREAT_RSS_*.json"]
    reports: List[Path] = []
    for pattern in patterns:
        reports.extend(runtime_root.glob(pattern))
    reports = sorted(reports, key=lambda item: item.stat().st_mtime, reverse=True)[:15]
    items = []
    for report in reports:
        try:
            payload = parse_json(report)
            metadata = payload.get("Metadata", {})
            items.append(
                {
                    "name": report.name,
                    "path": str(report),
                    "report_type": metadata.get("Mode") or metadata.get("AlertType") or report.name.split("_")[1],
                    "collection_time": metadata.get("CollectionTimeUtc") or "",
                    "summary": {
                        "MatchCount": payload.get("MatchCount"),
                        "ChangeCount": metadata.get("ChangeCount"),
                        "RelevantItemCount": metadata.get("RelevantItemCount"),
                    },
                }
            )
        except Exception:
            items.append({"name": report.name, "path": str(report), "report_type": "Unknown", "collection_time": "", "summary": {}})
    return items


def safe_path(candidate: str, roots: Iterable[Path]) -> Optional[Path]:
    if not candidate:
        return None
    resolved = Path(candidate).resolve()
    for root in roots:
        try:
            resolved.relative_to(root.resolve())
            return resolved
        except ValueError:
            continue
    return None


def render_metric(label: str, value: Any, tone: str = "") -> str:
    tone_class = f" status-{tone}" if tone else ""
    return f'<div class="metric"><div class="label">{esc(label)}</div><div class="value{tone_class}">{esc(value)}</div></div>'


def render_metric_time(label: str, value: Any, tone: str = "") -> str:
    tone_class = f" status-{tone}" if tone else ""
    return f'<div class="metric"><div class="label">{esc(label)}</div><div class="value{tone_class}">{render_metric_time_value(value)}</div></div>'


def format_trigger_type(trigger_type: Any) -> str:
    text = str(trigger_type or "").strip()
    if not text:
        return "Unknown"
    mapping = {
        "MSFT_TaskDailyTrigger": "Daily",
        "MSFT_TaskWeeklyTrigger": "Weekly",
        "MSFT_TaskMonthlyTrigger": "Monthly",
        "MSFT_TaskMonthlyDOWTrigger": "Monthly",
        "MSFT_TaskTimeTrigger": "One time",
        "MSFT_TaskBootTrigger": "At startup",
        "MSFT_TaskLogonTrigger": "At sign-in",
        "MSFT_TaskRegistrationTrigger": "On registration",
        "MSFT_TaskIdleTrigger": "When idle",
        "MSFT_TaskEventTrigger": "On event",
        "MSFT_TaskSessionStateChangeTrigger": "On session change",
    }
    if text in mapping:
        return mapping[text]
    cleaned = re.sub(r"^MSFT_Task", "", text)
    cleaned = re.sub(r"Trigger$", "", cleaned)
    cleaned = re.sub(r"([a-z])([A-Z])", r"\1 \2", cleaned)
    return cleaned or text


def format_repetition_interval(interval: Any) -> str:
    text = str(interval or "").strip()
    if not text or text.upper() == "N/A":
        return ""
    match = re.fullmatch(r"P(?:(?P<days>\d+)D)?(?:T(?:(?P<hours>\d+)H)?(?:(?P<minutes>\d+)M)?(?:(?P<seconds>\d+)S)?)?", text)
    if not match:
        return text
    parts = []
    units = (
        ("days", "day"),
        ("hours", "hour"),
        ("minutes", "minute"),
        ("seconds", "second"),
    )
    for key, label in units:
        raw_value = match.group(key)
        if not raw_value:
            continue
        value = int(raw_value)
        suffix = "" if value == 1 else "s"
        parts.append(f"{value} {label}{suffix}")
    if not parts:
        return ""
    return "Every " + " ".join(parts)


def describe_trigger_cadence(trigger: Dict[str, Any]) -> str:
    repeat = format_repetition_interval(trigger.get("RepetitionInterval"))
    if repeat:
        return repeat
    trigger_type = str(trigger.get("Type") or "").strip()
    fallback = {
        "MSFT_TaskDailyTrigger": "Daily",
        "MSFT_TaskWeeklyTrigger": "Weekly",
        "MSFT_TaskMonthlyTrigger": "Monthly",
        "MSFT_TaskMonthlyDOWTrigger": "Monthly",
        "MSFT_TaskTimeTrigger": "One time",
        "MSFT_TaskBootTrigger": "At startup",
        "MSFT_TaskLogonTrigger": "At sign-in",
        "MSFT_TaskRegistrationTrigger": "On registration",
        "MSFT_TaskIdleTrigger": "When idle",
        "MSFT_TaskEventTrigger": "On event",
        "MSFT_TaskSessionStateChangeTrigger": "On session change",
    }
    return fallback.get(trigger_type, "N/A")


def protection_score_tone(score: int) -> str:
    if score >= 85:
        return "ok"
    if score >= 60:
        return "medium"
    return "high"


def protection_control_tone(status: str) -> str:
    status = (status or "").lower()
    if status == "pass":
        return "ok"
    if status == "partial":
        return "medium"
    if status == "fail":
        return "high"
    return "info"


def alert_severity_tone(severity: str) -> str:
    text = (severity or "").strip().lower()
    if text in ("critical", "high"):
        return "high"
    if text in ("medium", "warning"):
        return "medium"
    return "info"


def get_local_pc_facts(status: Dict[str, Any]) -> Dict[str, str]:
    identify = status.get("Identify") or {}
    computer_name = str(identify.get("Hostname") or status.get("Metadata", {}).get("ComputerName") or platform.node() or "Unknown")
    try:
        current_user = getpass.getuser() or "Unknown"
    except Exception:
        current_user = "Unknown"
    edition = str(identify.get("WindowsEdition") or "").strip()
    version = str(identify.get("WindowsVersion") or "").strip()
    build = str(identify.get("WindowsBuild") or "").strip()
    if not edition:
        try:
            edition = platform.win32_edition() or "Unknown"
        except Exception:
            edition = "Unknown"
    if not version:
        try:
            version = platform.release() or "Unknown"
        except Exception:
            version = "Unknown"
    if not build:
        try:
            build = str(sys.getwindowsversion().build)
        except Exception:
            build = "Unknown"
    version_build = version if build in ("", "Unknown") else f"{version} (build {build})"

    def stringify(value: Any, fallback: str = "Unknown") -> str:
        if value in (None, ""):
            return fallback
        return str(value)

    return {
        "Hostname": computer_name,
        "Manufacturer": stringify(identify.get("Manufacturer")),
        "Model": stringify(identify.get("Model")),
        "WindowsEdition": edition if edition else "Unknown",
        "WindowsVersion": version if version else "Unknown",
        "WindowsBuild": build if build else "Unknown",
        "WindowsVersionBuild": version_build,
        "CurrentUser": stringify(identify.get("CurrentUser"), current_user),
        "BaselineTimestamp": str(status.get("State", {}).get("TripwireBaselineCollectionTimeUtc") or "Unknown"),
        "BaselineScope": stringify(identify.get("BaselineScope")),
        "UsersCount": stringify(identify.get("LocalUserCount"), "Not collected yet"),
        "AdminsCount": stringify(identify.get("LocalAdministratorCount"), "Not collected yet"),
        "SoftwareCount": stringify(identify.get("InstalledSoftwareCount"), "Not collected yet"),
        "ServicesCount": stringify(identify.get("RunningServiceCount"), "Not collected yet"),
        "TasksCount": stringify(identify.get("ScheduledTaskCount"), "Not collected yet"),
        "AutorunsCount": stringify(identify.get("AutorunCount"), "Not collected yet"),
        "NetworkAdaptersCount": stringify(identify.get("NetworkAdapterCount"), "Not collected yet"),
        "ListeningTcpPortsCount": stringify(identify.get("ListeningTcpPortCount"), "Not collected yet"),
        "SharedFoldersCount": stringify(identify.get("SharedFolderCount"), "Not collected yet"),
    }


def get_protect_control_metadata(control: Dict[str, Any]) -> Dict[str, str]:
    control_id = str(control.get("Id") or "")
    current = str(control.get("Current") or "Unknown")
    desired = str(control.get("Desired") or "Unknown")
    generic = {
        "risk": str(control.get("Message") or "This control does not currently meet the selected protection profile."),
        "evidence": f"Current state: {current}. Desired state: {desired}.",
        "fix_plan": "Review the target state, validate prerequisites, and schedule a controlled change window before modifying this PC.",
        "actionability": "Guidance only from this app.",
        "rollback": "Confirm a recent baseline, backup, and rollback plan before changing this control.",
        "exception": "Exception workflow is not implemented yet. Document the reason outside this app before accepting the risk.",
        "csf_function": "Protect",
    }
    specific = {
        "bitlocker_system_drive": {
            "risk": "Without BitLocker on the system drive, data at rest is easier to access if the PC is lost, stolen, or examined offline.",
            "evidence": f"BitLocker system drive status is currently {current}. The selected profile expects {desired}.",
            "fix_plan": "Confirm recovery-key handling, verify backup or key escrow location, then plan a controlled BitLocker enablement from Windows with administrative approval.",
            "actionability": "Can be fixed from Windows. Requires admin. Requires recovery-key handling. May take time.",
            "rollback": "Disabling BitLocker later can take time and may affect recovery expectations. Verify key escrow before any change.",
            "exception": "If disk encryption is intentionally deferred, document the business reason and compensating controls outside this app.",
        },
        "secure_boot": {
            "risk": "Without Secure Boot, the platform has weaker protection against low-level boot tampering.",
            "evidence": f"Secure Boot is currently {current}. The selected profile expects {desired}.",
            "fix_plan": "Review firmware compatibility, confirm a maintenance window, and prepare guided BIOS/UEFI steps for enabling Secure Boot.",
            "actionability": "Requires BIOS/UEFI firmware change. Requires reboot. Guidance only from this app.",
            "rollback": "Firmware changes can affect boot behavior. Confirm recovery options and firmware access before proceeding.",
            "exception": "If Secure Boot cannot be enabled due to hardware or firmware constraints, document the exception and alternative safeguards.",
        },
        "execution_policy": {
            "risk": "A weaker PowerShell execution policy increases the chance of unreviewed scripts running below the control level expected by the selected profile.",
            "evidence": f"PowerShell execution policy is currently {current}. The selected profile expects {desired}.",
            "fix_plan": "Review automation that depends on the current policy, test the stricter setting in a controlled session, then plan a LocalMachine change if approved.",
            "actionability": "Can be changed in Windows. LocalMachine scope requires admin. May affect scripts.",
            "rollback": "Changing execution policy can break existing automation. Validate monitoring and admin scripts before and after the change.",
            "exception": "If a weaker policy is required temporarily, document the dependency and review date outside this app.",
        },
        "winrm": {
            "risk": "WinRM left available when not needed increases remote management exposure and the attack surface.",
            "evidence": f"WinRM service state is currently {current}. The selected profile expects {desired}.",
            "fix_plan": "Inventory remote management dependencies, validate whether WinRM is required, then plan a controlled service or startup-mode change if approved.",
            "actionability": "Can be changed in Windows. Requires admin. May affect remote management tools.",
            "rollback": "Disabling WinRM can break management scripts, orchestration, or support workflows. Confirm dependencies first.",
            "exception": "If WinRM must remain available, document the dependency, access controls, and review cadence outside this app.",
        },
    }
    result = dict(generic)
    result.update(specific.get(control_id, {}))
    return result


def is_stale_timestamp(value: Any, hours: float) -> bool:
    dt = parse_display_datetime(value)
    if dt is None:
        return True
    age = datetime.now().astimezone() - dt
    return age.total_seconds() > (hours * 3600)


def compact_detail(summary: str, detail: str, *, css_class: str = "mini") -> str:
    detail_text = (detail or "").strip()
    if not detail_text:
        return ""
    return render_expandable_details(summary, esc(detail_text), css_class=css_class)


def render_expandable_details(summary: str, detail_html: str, *, css_class: str = "mini") -> str:
    if not (detail_html or "").strip():
        return ""
    return (
        f'<details class="inline-detail {esc(css_class)}">'
        f"<summary>{esc(summary)}</summary>"
        f'<div class="detail-body">{detail_html}</div>'
        f"</details>"
    )


def render_status_badge(label: Any, tone: str) -> str:
    return f'<span class="status-pill status-{esc(tone)}">{esc(label)}</span>'


def persona_allows_technical_detail(persona: Any) -> bool:
    profile = coerce_persona_profile(persona)
    return bool(profile.get("show_raw_evidence") or profile.get("show_diagnostics") or profile.get("report_language") == "technical")


def friendly_function_label(section_key: str, persona: Any) -> str:
    profile = coerce_persona_profile(persona)
    if persona_show_csf_codes(profile):
        return {
            "govern": "GV / Govern",
            "identify": "ID / Identify",
            "protect": "PR / Protect",
            "detect": "DE / Detect",
            "respond": "RS / Respond",
            "recover": "RC / Recover",
        }.get(section_key, section_key.title())
    return {
        "govern": "Set the plan",
        "identify": "Know this PC",
        "protect": "Keep it guarded",
        "detect": "Watch for changes",
        "respond": "Handle issues",
        "recover": "Get back to steady",
    }.get(section_key, section_key.title())


def dashboard_mood(model: Dict[str, Any]) -> Dict[str, str]:
    pending = len(model.get("alerts", {}).get("pending", []))
    attention = int((model.get("task_job_health") or {}).get("attention_tasks") or 0)
    score = int((model.get("protection_controls") or {}).get("score") or 0)
    if pending or score < 55:
        return {
            "tone": "critical",
            "mood_class": "action_needed",
            "headline": "Action is needed to restore protection.",
            "subtext": "A protection issue or active alert needs attention before this PC is fully steady again.",
            "tag": "Action needed",
        }
    if attention or score < 80:
        return {
            "tone": "warning",
            "mood_class": "needs_review",
            "headline": "A few things need care.",
            "subtext": "Your PC is protected, but a few improvements or reviews are ready for you.",
            "tag": "Needs review",
        }
    return {
        "tone": "calm",
        "mood_class": "steady",
        "headline": "Your PC is steady today.",
        "subtext": "Everything important is being watched, and your core protections are running.",
        "tag": "Steady today",
    }


def next_best_action(model: Dict[str, Any]) -> Dict[str, str]:
    item = (model.get("recommended_responses") or [{"title": "Review what changed", "summary": "Open the latest summary for this PC."}])[0]
    title = str(item.get("title") or "Review what changed")
    href = "/protect"
    lower = title.lower()
    if "alert" in lower or "respond" in lower:
        href = "/respond"
    elif "job" in lower or "monitor" in lower or "feed" in lower:
        href = "/detect"
    elif "baseline" in lower or "recover" in lower:
        href = "/recover"
    elif "pc" in lower or "identify" in lower:
        href = "/identify"
    return {"label": title, "href": href, "summary": str(item.get("summary") or "Open the next recommended area.")}


def render_status_strip(items: List[Dict[str, str]]) -> str:
    return '<div class="mood-strip">' + ''.join(
        f'<div class="mood-chip"><div class="label">{esc(item.get("label"))}</div><div class="value">{esc(item.get("value"))}</div></div>'
        for item in items
    ) + '</div>'


def render_care_tile(title: str, body: str, *, tone: str = "good", href: str = "") -> str:
    link_html = f'<div style="margin-top:10px"><a href="{esc(href)}">Open</a></div>' if href else ""
    return f'<div class="care-tile {esc(tone)}"><h4>{esc(title)}</h4><p>{esc(body)}</p>{link_html}</div>'


def render_recent_activity(items: List[Dict[str, str]]) -> str:
    return '<div class="activity-list">' + ''.join(
        f'<div class="activity-item"><strong>{esc(item.get("title"))}</strong><div>{esc(item.get("body"))}</div><div class="mini">{esc(item.get("meta"))}</div></div>'
        for item in items
    ) + '</div>'


def render_section_card(kicker: str, title: str, body_html: str, *, extra_classes: str = "panel stack", lead_html: str = "") -> str:
    lead = f"{lead_html}\n" if lead_html else ""
    return f"""
<section class="{esc(extra_classes)}">
  <div class="kicker">{esc(kicker)}</div>
  <h2>{esc(title)}</h2>
  {lead}{body_html}
</section>
"""


def render_metric_card(metric: Dict[str, Any]) -> str:
    label = metric.get("label") or ""
    value = metric.get("value")
    tone = metric.get("tone") or ""
    is_time = bool(metric.get("is_time"))
    if is_time:
        return render_metric_time(label, value, tone)
    return render_metric(label, value, tone)


def render_recommended_response(item: Dict[str, str]) -> str:
    tone = item.get("tone") or "info"
    card_class = "critical" if tone == "high" else ("warning" if tone == "medium" else "calm")
    return f"""
    <div class="focus-card {card_class}">
      <div class="focus-label">Priority {esc(item.get('priority'))}</div>
      <div class="focus-title">{esc(item.get('title'))}</div>
      <div class="focus-copy">{esc(item.get('summary'))}</div>
      <div class="focus-meta">{esc(item.get('detail'))}</div>
    </div>
"""


def render_recovery_card(recovery: Dict[str, Any], recovery_rows: str, recovery_recommendations: str) -> str:
    tone = "medium" if recovery["Overall"] == "Limited" else ("high" if recovery["Overall"] == "Poor" else "info")
    return f"""
<section class="panel stack" style="margin-top:18px">
  <div class="kicker">Recover</div>
  <div class="task-head">
    <div>
      <h2>Recovery readiness</h2>
      <div class="mini">This is a read-only view of whether the local PC has enough recovery context to roll back safely after remediation.</div>
    </div>
    <div>{render_status_badge(recovery['Overall'], tone)}</div>
  </div>
  <table><thead><tr><th>Recovery item</th><th>Status</th><th>Current</th><th>Notes</th></tr></thead><tbody>{recovery_rows}</tbody></table>
  <div class="focus-card warning">
    <div class="focus-label">Recovery recommendations</div>
    <div class="focus-copy">
      <ul style="margin:0; padding-left:18px;">{recovery_recommendations}</ul>
    </div>
  </div>
</section>
"""


def render_protection_control_row(control: Dict[str, Any]) -> str:
    return (
        f"<tr><td>{esc(control.get('Title'))}</td>"
        f"<td>{esc(control.get('Current'))}</td>"
        f"<td>{render_status_badge(control.get('Status'), protection_control_tone(control.get('Status')))}</td></tr>"
    )


def render_detect_focus_card(card: Dict[str, Any]) -> str:
    rows = "".join(
        f"<tr><td>{esc(item.get('label'))}</td><td>{esc(item.get('value'))}</td></tr>"
        for item in (card.get("items") or [])
    ) or "<tr><td colspan='2' class='mini'>No data available.</td></tr>"
    links = "".join(
        f'<div class="mini"><a href="{esc(link.get("href"))}">{esc(link.get("label"))}</a></div>'
        for link in (card.get("links") or [])
    )
    note_html = f'<div class="mini">{esc(card.get("note"))}</div>' if card.get("note") else ""
    return f"""
    <div class="focus-card {esc(card.get("tone") or "report")}">
      <div class="focus-label">{esc(card.get("label"))}</div>
      <div class="focus-title">{esc(card.get("title"))}</div>
      <div class="focus-copy">{esc(card.get("copy"))}</div>
      <table><tbody>{rows}</tbody></table>
      {note_html}
      {links}
    </div>
"""


def render_respond_action_links(alert: Dict[str, Any], lifecycle_state: str) -> str:
    encoded = urllib.parse.quote(alert["path"], safe="")
    report_path = alert.get("source_report") or alert.get("path")
    report_href = f"/report?path={urllib.parse.quote(str(report_path), safe='')}" if report_path else f"/alert?path={encoded}"
    export_href = f"/alert?path={encoded}"
    anchor = re.sub(r"[^a-z0-9]+", "-", str(alert.get("name") or alert.get("title") or "alert").lower()).strip("-") or "alert"
    mark_expected_detail = "Mark expected is a planning-only step in this UI. Document expected changes outside the app until alert workflow state is implemented."
    return (
        '<div class="task-actions" style="margin-top:8px">'
        f'<a class="btn" href="#alert-{esc(anchor)}-ack">Acknowledge</a>'
        f'<a class="btn" href="#alert-{esc(anchor)}-investigate">Investigate</a>'
        f'<a class="btn" href="{esc(report_href)}">View evidence</a>'
        f'<a class="btn" href="{esc(export_href)}">Export alert</a>'
        f'<a class="btn" href="#alert-{esc(anchor)}-expected">Mark expected</a>'
        '</div>'
        f'<details class="inline-detail mini" id="alert-{esc(anchor)}-ack"><summary>Acknowledge</summary><div class="detail-body">Lifecycle state is currently {esc(lifecycle_state)}. Use this step to note that the alert has been seen and is awaiting human review. No backend state is changed yet.</div></details>'
        f'<details class="inline-detail mini" id="alert-{esc(anchor)}-investigate"><summary>Investigate</summary><div class="detail-body">Open the alert evidence, review the related report, and compare the alert against recent expected maintenance or software changes on this PC.</div></details>'
        f'<details class="inline-detail mini" id="alert-{esc(anchor)}-expected"><summary>Mark expected</summary><div class="detail-body">{esc(mark_expected_detail)}</div></details>'
    )


def build_recovery_readiness(status: Dict[str, Any], recent_reports: List[Dict[str, Any]], archive_alerts: List[Dict[str, Any]]) -> Dict[str, Any]:
    baseline_value = status.get("State", {}).get("TripwireBaselineCollectionTimeUtc")
    has_baseline = bool(parse_display_datetime(baseline_value))
    baseline_status = "Available" if has_baseline else "Missing"

    rollback_record_count = len(recent_reports) + len(archive_alerts)
    if has_baseline and rollback_record_count > 0:
        rollback_status = "Available"
        rollback_message = f"{rollback_record_count} local report or alert record(s) available for rollback context."
    elif has_baseline:
        rollback_status = "Limited"
        rollback_message = "A baseline exists, but few retained rollback records are available."
    else:
        rollback_status = "Unknown"
        rollback_message = "No current baseline is available to pair with rollback records."

    recommendations: List[str] = []
    if not has_baseline:
        recommendations.append("Create a fresh tripwire baseline before relying on recovery comparisons.")
    if rollback_status != "Available":
        recommendations.append("Retain recent reports and archived alerts so post-change rollback context is preserved.")
    recommendations.append("Restore point status is not collected yet; verify it manually before risky changes.")
    recommendations.append("Backup status is not collected yet; confirm a usable backup before remediation.")
    recommendations.append("Post-remediation validation is not implemented yet; rerun tripwire and IOC scans after changes.")

    overall = "Poor" if not has_baseline else ("Limited" if rollback_status != "Available" else "Moderate")
    return {
        "Overall": overall,
        "LastKnownGoodBaseline": {
            "Status": baseline_status,
            "Value": baseline_value or "Unknown",
            "Message": "Tripwire baselines are the last known-good comparison point for this PC."
        },
        "RollbackRecords": {
            "Status": rollback_status,
            "Value": f"{rollback_record_count} record(s)" if rollback_record_count else "None",
            "Message": rollback_message,
        },
        "RestorePointStatus": {
            "Status": "Unknown",
            "Value": "Unknown",
            "Message": "System Restore state is not collected by this dashboard yet.",
        },
        "BackupStatus": {
            "Status": "Unknown",
            "Value": "Unknown",
            "Message": "Backup state is not collected by this dashboard yet.",
        },
        "PostRemediationValidation": {
            "Status": "Not implemented yet",
            "Value": "Not implemented yet",
            "Message": "Automated post-remediation validation workflow is not implemented yet.",
        },
        "Recommendations": recommendations,
    }


def build_recommended_responses(
    status: Dict[str, Any],
    tasks: List[Dict[str, Any]],
    protection: Dict[str, Any],
    pending_alerts: List[Dict[str, Any]],
    recent_reports: List[Dict[str, Any]],
    archive_alerts: List[Dict[str, Any]],
) -> List[Dict[str, str]]:
    responses: List[Dict[str, str]] = []

    if pending_alerts:
        top = pending_alerts[0]
        responses.append({
            "priority": "1",
            "tone": "high",
            "title": "Review pending alert first",
            "summary": top.get("title") or "Pending alert",
            "detail": top.get("message") or "A pending alert is waiting for review and should be handled before other posture work.",
        })

    unhealthy = []
    for task in tasks:
        result = classify_task_result(task)
        if result["tone"] in ("medium", "high"):
            unhealthy.append((task, result))
    if unhealthy:
        task, result = unhealthy[0]
        responses.append({
            "priority": "2",
            "tone": result["tone"],
            "title": "Stabilize monitoring job",
            "summary": task.get("Name") or "Monitoring job",
            "detail": result["message"],
        })

    weak_controls = []
    for control in protection.get("Controls") or []:
        if control.get("Status") in ("Fail", "Partial"):
            weak_controls.append(control)
    if weak_controls:
        control = weak_controls[0]
        responses.append({
            "priority": "3",
            "tone": "medium" if control.get("Status") == "Partial" else "high",
            "title": "Review protection drift",
            "summary": control.get("Title") or "Protection control",
            "detail": control.get("Message") or "This protection control does not currently meet the selected profile.",
        })

    baseline_missing = not status.get("State", {}).get("TripwireBaselineCollectionTimeUtc")
    stale_report = all(
        is_stale_timestamp(
            (status.get("LatestArtifacts") or {}).get(key, {}).get("LastWriteTimeUtc"),
            48,
        )
        for key in ("LatestIocReport", "LatestTripwireReport", "LatestThreatRssReport")
    )
    if baseline_missing or stale_report:
        detail_parts = []
        if baseline_missing:
            detail_parts.append("Tripwire baseline is missing.")
        if stale_report:
            detail_parts.append("Recent evidence reports are stale or missing.")
        responses.append({
            "priority": "4",
            "tone": "medium",
            "title": "Refresh baseline or evidence",
            "summary": "Baseline or report freshness needs attention",
            "detail": " ".join(detail_parts),
        })

    recovery = build_recovery_readiness(status, recent_reports, archive_alerts)
    if recovery["Overall"] in ("Poor", "Limited"):
        responses.append({
            "priority": "5",
            "tone": "medium",
            "title": "Improve recovery readiness",
            "summary": f'Recovery posture is {recovery["Overall"].lower()}',
            "detail": recovery["Recommendations"][0],
        })

    if not responses:
        responses.append({
            "priority": "0",
            "tone": "ok",
            "title": "No immediate response needed",
            "summary": "Protection is healthy",
            "detail": "There are no pending alerts, the monitoring jobs are healthy, and no priority posture issue currently outranks normal review.",
        })

    return responses


def render_task(task: Dict[str, Any]) -> str:
    result_status = classify_task_result(task)
    actions = task.get("Actions") or []
    triggers = task.get("Triggers") or []
    action_markup = "".join(
        f"<tr><td>{esc(action.get('Execute'))}</td><td>{esc(action.get('Arguments'))}</td><td>{esc(action.get('WorkingDirectory') or 'N/A')}</td></tr>"
        for action in actions
    ) or "<tr><td colspan='3' class='mini'>No actions found.</td></tr>"
    trigger_markup = "".join(
        f"<tr><td>{esc(format_trigger_type(trigger.get('Type')))}</td><td>{esc(pretty_time(trigger.get('StartBoundary') or 'N/A'))}</td><td>{esc(describe_trigger_cadence(trigger))}</td></tr>"
        for trigger in triggers
    ) or "<tr><td colspan='3' class='mini'>No triggers found.</td></tr>"
    raw_code_markup = f'<div class="mini" style="margin-top:6px">Raw code: {esc(result_status["raw"])}</div>' if result_status["raw"] else ""
    baseline_action_markup = ""
    if task.get("Name") == "Codex Host Tripwire":
        baseline_action_markup = """
      <form method="post" action="/run-tripwire-baseline">
        <button class="btn" type="submit">Run baseline</button>
      </form>
"""
    return f"""
<div class="task">
  <div class="task-head">
    <div>
      <div class="task-name">{esc(task.get("Name"))}</div>
      <div class="task-meta">{esc(task.get("State") or "Missing")} • Enabled={esc(task.get("Enabled"))}</div>
      <div style="margin-top:10px">
        {render_status_badge(result_status['label'], result_status['tone'])}
        <span class="mini" style="margin-left:8px">{esc(result_status['message'])}</span>
        {raw_code_markup}
      </div>
    </div>
    <div class="task-actions">
      <form method="post" action="/run-task">
        <input type="hidden" name="task_name" value="{esc(task.get("Name"))}">
        <button class="btn primary" type="submit">Run now</button>
      </form>
      {baseline_action_markup}
    </div>
  </div>
  <dl class="kv">
    <dt>Author</dt><dd>{esc(task.get("Author") or "N/A")}</dd>
    <dt>Principal</dt><dd>{esc(task.get("Principal") or "N/A")} ({esc(task.get("RunLevel") or "N/A")})</dd>
    <dt>Last run</dt><dd>{esc(pretty_time(task.get("LastRunTime") or "N/A"))}</dd>
    <dt>Next run</dt><dd>{esc(pretty_time(task.get("NextRunTime") or "N/A"))}</dd>
    <dt>Description</dt><dd>{esc(task.get("Description") or "N/A")}</dd>
  </dl>
  <details class="task-detail">
    <summary>Task internals</summary>
    <div class="stack" style="margin-top:14px">
      <div>
        <h3>Actions</h3>
        <table><thead><tr><th>Execute</th><th>Arguments</th><th>Working Dir</th></tr></thead><tbody>{action_markup}</tbody></table>
      </div>
      <div>
        <h3>Triggers</h3>
        <table><thead><tr><th>Schedule</th><th>Start</th><th>Cadence</th></tr></thead><tbody>{trigger_markup}</tbody></table>
      </div>
    </div>
  </details>
</div>
"""


def render_alert_row(alert: Dict[str, Any], *, lifecycle_state: str = "", show_actions: bool = False) -> str:
    encoded = urllib.parse.quote(alert["path"], safe="")
    message = str(alert.get("message") or "").strip()
    if message and len(message) > 120:
        message_markup = compact_detail("Details", message)
    elif message:
        message_markup = f'<div class="mini">{esc(message)}</div>'
    else:
        message_markup = ""
    severity_text = str(alert.get("severity") or "Unknown")
    severity_markup = render_status_badge(severity_text, alert_severity_tone(severity_text))
    lifecycle_markup = render_status_badge(lifecycle_state, "info" if lifecycle_state == "New" else "ok") if lifecycle_state else ""
    action_markup = render_respond_action_links(alert, lifecycle_state) if show_actions else ""
    return f"""
<tr>
  <td>{severity_markup}</td>
  <td><a href="/alert?path={encoded}">{esc(alert.get("title"))}</a>{message_markup}{action_markup}</td>
  <td>{lifecycle_markup}</td>
  <td>{esc(alert.get("change_count") if alert.get("change_count") is not None else "—")}</td>
  <td>{esc(pretty_time(alert.get("collection_time") or "—"))}</td>
</tr>
"""


def render_report_row(report: Dict[str, Any]) -> str:
    encoded = urllib.parse.quote(report["path"], safe="")
    summary_parts = [f"{key}={value}" for key, value in report.get("summary", {}).items() if value not in (None, "", 0)]
    summary_text = ", ".join(summary_parts) if summary_parts else "No summary fields"
    summary_markup = compact_detail("View summary", summary_text) if len(summary_text) > 90 else esc(summary_text)
    return f"""
<tr>
  <td><a href="/report?path={encoded}">{esc(report.get("name"))}</a></td>
  <td>{esc(report.get("report_type"))}</td>
  <td>{esc(pretty_time(report.get("collection_time") or "—"))}</td>
  <td>{summary_markup}</td>
</tr>
"""


def render_protect_attention_control(control: Dict[str, Any]) -> str:
    meta = get_protect_control_metadata(control)
    control_anchor = f"protect-{re.sub(r'[^a-z0-9]+', '-', str(control.get('Id') or control.get('Title') or 'control').lower()).strip('-')}"
    details_html = f"""
        <div id="{control_anchor}-risk" class="focus-card warning">
          <div class="focus-label">Explain risk</div>
          <div class="focus-copy">{esc(meta["risk"])}</div>
        </div>
        <div id="{control_anchor}-evidence" class="focus-card report">
          <div class="focus-label">View evidence</div>
          <div class="focus-copy">Current state: {esc(control.get("Current"))}</div>
          <div class="focus-copy">Desired state: {esc(control.get("Desired"))}</div>
          <div class="focus-meta">{esc(meta["evidence"])}</div>
        </div>
        <div id="{control_anchor}-plan" class="focus-card report">
          <div class="focus-label">Create fix plan</div>
          <div class="focus-copy">{esc(meta["fix_plan"])}</div>
          <div class="focus-meta">Actionability: {esc(meta["actionability"])}</div>
        </div>
        <div id="{control_anchor}-exception" class="focus-card calm">
          <div class="focus-label">Accept exception</div>
          <div class="focus-copy">{esc(meta["exception"])}</div>
          <div class="focus-meta">No Windows changes are made from this panel.</div>
        </div>
        <dl class="kv">
          <dt>Current state</dt><dd>{esc(control.get("Current"))}</dd>
          <dt>Desired state</dt><dd>{esc(control.get("Desired"))}</dd>
          <dt>Why it matters</dt><dd>{esc(meta["risk"])}</dd>
          <dt>Evidence</dt><dd>{esc(meta["evidence"])}</dd>
          <dt>Fix plan</dt><dd>{esc(meta["fix_plan"])}</dd>
          <dt>Actionability</dt><dd>{esc(meta["actionability"])}</dd>
          <dt>Rollback considerations</dt><dd>{esc(meta["rollback"])}</dd>
          <dt>CSF function</dt><dd>{esc(meta["csf_function"])}</dd>
        </dl>
"""
    return f"""
  <div class="task">
    <div class="task-head">
      <div>
        <div class="task-name">{esc(control.get("Title"))}</div>
        <div class="task-meta">Current: {esc(control.get("Current"))} • Desired: {esc(control.get("Desired"))}</div>
        <div style="margin-top:10px">
          {render_status_badge(control.get("Status"), protection_control_tone(control.get("Status")))}
          <span class="mini" style="margin-left:8px">{esc(meta["actionability"])}</span>
        </div>
      </div>
      <div class="task-actions">
        <a class="btn" href="#{control_anchor}-risk">Explain risk</a>
        <a class="btn" href="#{control_anchor}-evidence">View evidence</a>
        <a class="btn" href="#{control_anchor}-plan">Create fix plan</a>
        <a class="btn" href="#{control_anchor}-exception">Accept exception</a>
      </div>
    </div>
    <details class="task-detail">
      <summary>Control details</summary>
      <div class="stack" style="margin-top:14px">{details_html}</div>
    </details>
  </div>
"""


def build_snapshot(config: AppConfig) -> Dict[str, Any]:
    status = get_status_snapshot(config)
    direct_task_details = get_task_details(TASK_NAMES)
    task_details = merge_task_details(TASK_NAMES, direct_task_details, status.get("ScheduledTasks") or [])
    installed_task_names = {str(task.get("Name")) for task in task_details if task.get("Installed")}
    if installed_task_names:
        status["ScheduledTasks"] = task_details
        findings = []
        for finding in status.get("HealthFindings") or []:
            message = str(finding.get("Message") or "")
            if message.startswith("Scheduled task missing: "):
                task_name = message.split(": ", 1)[1]
                if task_name in installed_task_names:
                    continue
            findings.append(finding)
        status["HealthFindings"] = findings
    indicators = query_indicator_stats(config.state_db_path)
    pending_alerts = list_alert_records(config.alert_inbox_path, "pending")
    archive_alerts = list_alert_records(config.alert_archive_path, "archive")
    recent_reports = list_recent_reports(config.runtime_root)
    return {
        "status": status,
        "task_details": task_details,
        "indicators": indicators,
        "pending_alerts": pending_alerts,
        "archive_alerts": archive_alerts,
        "recent_reports": recent_reports,
    }


def _assert_status_badge_rendering() -> None:
    assert 'status-ok' in render_status_badge("Healthy", "ok")


def _assert_recommended_response_priority(responses: List[Dict[str, str]]) -> None:
    priorities = [int(item["priority"]) for item in responses]
    assert priorities == sorted(priorities), "Recommended responses must stay sorted by priority."


def _assert_recovery_readiness_output(recovery: Dict[str, Any]) -> None:
    required_keys = {
        "Overall",
        "LastKnownGoodBaseline",
        "RollbackRecords",
        "RestorePointStatus",
        "BackupStatus",
        "PostRemediationValidation",
        "Recommendations",
    }
    assert required_keys.issubset(recovery.keys()), "Recovery readiness model is missing required keys."


def _assert_protection_control_sorting(controls: List[Dict[str, Any]]) -> None:
    rank = {"Fail": 0, "Partial": 1, "Unknown": 2, "Pass": 3}
    order = [rank.get(str(item.get("Status")), 9) for item in controls]
    assert order == sorted(order), "Protection controls must stay sorted by severity."


def build_dashboard_model(config: AppConfig, snapshot: Dict[str, Any], message: str = "") -> Dict[str, Any]:
    status = snapshot["status"]
    protection = status.get("Protection") or {}
    indicators = snapshot["indicators"]
    pending_alerts = snapshot["pending_alerts"]
    archive_alerts = snapshot["archive_alerts"]
    recent_reports = snapshot["recent_reports"]
    tasks = snapshot["task_details"]
    findings = status.get("HealthFindings") or []
    task_states = [classify_task_result(task) for task in tasks]
    healthy_tasks = sum(1 for item in task_states if item["label"] == "Healthy")
    attention_tasks = sum(1 for item in task_states if item["tone"] in ("medium", "high"))
    top_pending = pending_alerts[0] if pending_alerts else None
    top_report = recent_reports[0] if recent_reports else None
    local_pc = get_local_pc_facts(status)
    persona_profiles = load_persona_profiles(config.repo_root)
    system_profiles = load_system_profiles(config.repo_root)
    effective_persona = get_effective_persona(config, persona_profiles)
    effective_system_profile = get_effective_system_profile(status, system_profiles)
    tasks_by_name = {str(task.get("Name")): task for task in tasks}
    latest_artifacts = status.get("LatestArtifacts") or {}
    coverage = status.get("Coverage") or {}
    latest_ioc_hash_coverage = coverage.get("LatestIocHashCoverage") or {}
    latest_tripwire_posture_summary = coverage.get("LatestTripwirePostureSummary") or status.get("State", {}).get("LatestTripwireDriftSummary") or {}
    protection_profile = protection.get("SelectedProfile") or {}
    protection_profiles = protection.get("AvailableProfiles") or []
    sorted_controls = sorted(
        protection.get("Controls") or [],
        key=lambda item: {"Fail": 0, "Partial": 1, "Unknown": 2, "Pass": 3}.get(str(item.get("Status")), 9),
    )
    actionable_controls = [control for control in sorted_controls if str(control.get("Status")) in ("Fail", "Partial")]
    passing_controls = [control for control in sorted_controls if str(control.get("Status")) == "Pass"]
    recommended_responses = build_recommended_responses(status, tasks, protection, pending_alerts, recent_reports, archive_alerts)
    recovery = build_recovery_readiness(status, recent_reports, archive_alerts)
    detect_task_names = [
        "Codex Threat Feed Import",
        "Codex Threat RSS Monitor",
        "Codex IOC Daily Scan",
        "Codex Host Tripwire",
    ]
    respond_task_names = ["Codex Alert Notifier"]
    govern_task_names = TASK_NAMES
    latest_ioc_report = latest_artifacts.get("LatestIocReport") or {}
    latest_tripwire_report = latest_artifacts.get("LatestTripwireReport") or {}
    latest_rss_report = latest_artifacts.get("LatestThreatRssReport") or {}
    ioc_report_time = latest_ioc_report.get("LastWriteTimeUtc") or ""
    tripwire_report_time = latest_tripwire_report.get("LastWriteTimeUtc") or ""
    rss_report_time = latest_rss_report.get("LastWriteTimeUtc") or ""
    rss_last_run = status["State"]["ThreatRssLastRunUtc"] or ""
    baseline_time = status["State"]["TripwireBaselineCollectionTimeUtc"] or ""
    latest_ioc_report_entry = next(
        (
            report
            for report in recent_reports
            if str(report.get("path") or "") == str(latest_ioc_report.get("Path") or "")
        ),
        None,
    )
    latest_ioc_match_count = (
        (latest_ioc_report_entry or {}).get("summary", {}).get("MatchCount")
        if latest_ioc_report_entry
        else None
    )
    baseline_hash_status = str(
        coverage.get("BaselineHashIndexStatus")
        or latest_ioc_hash_coverage.get("baseline_hash_index_status")
        or "unavailable"
    )
    baseline_hash_count = coverage.get("LatestBaselineHashCount")
    baseline_hash_id = coverage.get("LatestBaselineId") or latest_ioc_hash_coverage.get("baseline_id") or ""
    total_sha256_corpus = latest_ioc_hash_coverage.get("total_sha256_corpus")
    intel_stale = any(is_stale_timestamp(value, 48) for value in (ioc_report_time, rss_report_time, rss_last_run))
    attention_job_names = []
    healthy_job_names = []
    for task in tasks:
        classification = classify_task_result(task)
        if classification["tone"] in ("medium", "high"):
            attention_job_names.append((task, classification))
        elif classification["label"] == "Healthy":
            healthy_job_names.append(task)

    drift_evidence = "Unknown"
    top_tripwire_alert = next((alert for alert in pending_alerts if "TRIPWIRE" in str(alert.get("name") or "").upper()), None)
    if top_tripwire_alert:
        drift_evidence = f"Pending alert: {top_tripwire_alert.get('title') or 'Tripwire change detected'}"
    elif latest_tripwire_report.get("Path"):
        drift_evidence = "Recent tripwire evidence available"

    response_required_count = 0
    if latest_tripwire_posture_summary:
        response_required_count = int(latest_tripwire_posture_summary.get("response_required_count") or 0)
        if response_required_count == 0:
            response_required_count = sum(
                int(latest_tripwire_posture_summary.get(key) or 0)
                for key in ("security_control_drift_count", "trusted_tool_drift_count", "logging_audit_drift_count", "app_integrity_drift_count")
            )
    detect_summary = (
        "This PC has current threat intelligence and recent tripwire checks. No response-required findings are open, and any expected or accepted posture changes remain recorded for auditability."
        if not intel_stale and not top_pending and response_required_count == 0
        else "This PC needs review in Detect because threat intelligence, host evidence, or monitoring jobs are not fully current."
    )
    if baseline_hash_status in ("empty", "unavailable"):
        hash_coverage_line = "Baseline hash IOC coverage is not available yet."
    else:
        hash_coverage_line = (
            "Hash IOC coverage: current process hashes {0}, current recent-file hashes {1}, "
            "latest indexed baseline hashes {2}, total SHA-256 corpus {3}, match count {4}."
        ).format(
            latest_ioc_hash_coverage.get("process_hashes_checked", "Unknown"),
            latest_ioc_hash_coverage.get("recent_file_hashes_checked", "Unknown"),
            latest_ioc_hash_coverage.get("baseline_hashes_checked", "Unknown"),
            total_sha256_corpus if total_sha256_corpus not in (None, "") else "Unknown",
            latest_ioc_match_count if latest_ioc_match_count not in (None, "") else "Unknown",
        )
    respond_summary = (
        "This PC has pending alerts that should be reviewed."
        if pending_alerts
        else ("Alert delivery is configured, but no active incidents are open." if any(task.get("Name") == "Codex Alert Notifier" and task.get("Installed") for task in tasks) else "No pending alerts are waiting for triage.")
    )
    triage_steps = (
        [
            "Review the alert evidence.",
            "Check whether the change was expected.",
            "Export evidence if the alert looks suspicious.",
            "Run existing read-only scans if appropriate.",
            "Move to Recover after cleanup and validation.",
        ]
        if pending_alerts
        else [
            "No active response required.",
            "Review archived alerts if needed.",
            "Keep monitoring enabled.",
        ]
    )

    report_focus = None
    if top_report:
        report_focus = {
            "label": "Latest evidence",
            "title": top_report.get("name"),
            "copy": f"{top_report.get('report_type')} collected {pretty_time(top_report.get('collection_time') or '')}.",
            "tone": "report",
        }
    detection_signal = None
    if top_pending:
        detection_signal = {
            "label": "Active detection",
            "title": top_pending.get("title") or "Pending alert",
            "copy": top_pending.get("message") or "A detection has been queued for response.",
            "meta": f"{top_pending.get('severity') or 'Unknown'} • {pretty_time(top_pending.get('collection_time') or '')}",
            "tone": "critical",
        }
    elif top_report:
        detection_signal = report_focus
    else:
        detection_signal = {
            "label": "Active detection",
            "title": "No immediate detection signal",
            "copy": "The monitor does not currently have a pending alert or a newly surfaced evidence item requiring immediate review.",
            "tone": "calm",
        }

    model = {
        "app": {
            "title": "Codex Monitor UI",
            "kicker": "Codex Monitor",
            "headline": "Protection status, without the debugging noise.",
            "lede": "See whether protection is healthy, what needs action now, and when the monitoring jobs last ran. Engineering details are still available, but they no longer crowd the main screen.",
            "message": message,
            "ui_persona": config.ui_persona,
            "persona_profile": effective_persona,
            "available_personas": [persona_profiles[key] for key in ["user", "advanced_user", "csf_native", "analyst", "tech"] if key in persona_profiles] + [persona_profiles[key] for key in persona_profiles.keys() if key not in DEFAULT_PERSONA_PROFILES],
            "system_profile": effective_system_profile,
            "profile_catalog_paths": {key: str(value) for key, value in profile_catalog_paths(config.repo_root).items()},
        },
        "this_pc": {
            "identity": local_pc,
            "focus": {
                "label": "Local host context",
                "title": local_pc["Hostname"],
                "copy": "This dashboard monitors the Windows PC it is running on. Tripwire baselines define the normal local state so later checks can compare the same machine in a compatible context.",
                "meta": f'{local_pc["Manufacturer"]} • {local_pc["Model"]} • {local_pc["WindowsEdition"]} • {local_pc["WindowsVersionBuild"]}',
            },
            "asset_scope_metrics": [
                {"label": "Local users", "value": local_pc["UsersCount"]},
                {"label": "Local admins", "value": local_pc["AdminsCount"]},
                {"label": "Installed software", "value": local_pc["SoftwareCount"]},
                {"label": "Running services", "value": local_pc["ServicesCount"]},
                {"label": "Scheduled tasks", "value": local_pc["TasksCount"]},
                {"label": "Autoruns", "value": local_pc["AutorunsCount"]},
                {"label": "Network adapters", "value": local_pc["NetworkAdaptersCount"]},
                {"label": "Listening TCP ports", "value": local_pc["ListeningTcpPortsCount"]},
                {"label": "Shared folders", "value": local_pc["SharedFoldersCount"]},
            ],
            "evidence_metrics": [
                {"label": "Tripwire baseline", "value": status["State"]["TripwireBaselineCollectionTimeUtc"] or "Missing", "is_time": True},
                {"label": "Latest IOC report", "value": pretty_time((status.get("LatestArtifacts") or {}).get("LatestIocReport", {}).get("LastWriteTimeUtc") or "Missing")},
                {"label": "Latest Tripwire report", "value": pretty_time((status.get("LatestArtifacts") or {}).get("LatestTripwireReport", {}).get("LastWriteTimeUtc") or "Missing")},
                {"label": "Latest RSS report", "value": pretty_time((status.get("LatestArtifacts") or {}).get("LatestThreatRssReport", {}).get("LastWriteTimeUtc") or "Missing")},
            ],
        },
        "summary_metrics": [
            {"label": "Protection score", "value": f"{int(protection.get('Score') or 0)}/100"},
            {"label": "Pending alerts", "value": status["State"]["PendingAlertCount"]},
            {"label": "Healthy jobs", "value": f"{healthy_tasks}/{len(tasks)}"},
            {"label": "Jobs needing review", "value": attention_tasks},
            {"label": "Indicators", "value": indicators["indicator_count"]},
            {"label": "Tripwire baseline", "value": status["State"]["TripwireBaselineCollectionTimeUtc"] or "Missing", "is_time": True},
            {"label": "RSS last run", "value": status["State"]["ThreatRssLastRunUtc"] or "Missing", "is_time": True},
        ],
        "section_order": ["govern", "identify", "protect", "detect", "respond", "recover"],
        "recommended_responses": recommended_responses,
        "recovery_readiness": recovery,
        "protection_controls": {
            "score": int(protection.get("Score") or 0),
            "profile": protection_profile,
            "profiles": protection_profiles,
            "sorted": sorted_controls,
            "actionable": actionable_controls,
            "passing": passing_controls,
        },
        "alerts": {
            "pending": pending_alerts,
            "archived": archive_alerts,
        },
        "reports": {
            "recent": recent_reports,
            "top": top_report,
            "detection_signal": detection_signal,
            "report_focus": report_focus,
        },
        "task_job_health": {
            "healthy_tasks": healthy_tasks,
            "attention_tasks": attention_tasks,
            "all": tasks,
            "by_name": tasks_by_name,
            "groups": {
                "detect": detect_task_names,
                "respond": respond_task_names,
                "govern": govern_task_names,
            },
        },
        "csf_sections": {
            "govern": {"findings": findings},
            "identify": {},
            "protect": {},
            "detect": {
                "summary": detect_summary,
                "hash_coverage_line": hash_coverage_line,
                "subcards": [
                    {
                        "label": "Threat Intel Freshness",
                        "title": "External intelligence is " + ("stale" if intel_stale else "current"),
                        "copy": "Indicator feeds and advisory polling show whether this PC is using recent threat intelligence.",
                        "tone": "warning" if intel_stale else "report",
                        "items": [
                            {"label": "Indicator count", "value": indicators["indicator_count"]},
                            {"label": "Latest IOC report", "value": pretty_time(ioc_report_time or "Missing")},
                            {"label": "Latest RSS report", "value": pretty_time(rss_report_time or "Missing")},
                            {"label": "Threat RSS last run", "value": pretty_time(rss_last_run or "Missing")},
                            {"label": "Status", "value": "Stale" if intel_stale else "Fresh"},
                            {"label": "Baseline hash index", "value": baseline_hash_status},
                            {"label": "Baseline ID", "value": baseline_hash_id or "Not indexed yet"},
                            {"label": "Baseline hash count", "value": baseline_hash_count if baseline_hash_count not in (None, "") else "Unknown"},
                            {"label": "Total SHA-256 corpus", "value": total_sha256_corpus if total_sha256_corpus not in (None, "") else "Unknown"},
                            {"label": "Match count", "value": latest_ioc_match_count if latest_ioc_match_count not in (None, "") else "Unknown"},
                        ],
                        "links": [
                            {"label": "Open latest IOC report", "href": f"/report?path={urllib.parse.quote(str(latest_ioc_report.get('Path') or ''), safe='')}"} if latest_ioc_report.get("Path") else None,
                            {"label": "Open latest RSS report", "href": f"/report?path={urllib.parse.quote(str(latest_rss_report.get('Path') or ''), safe='')}"} if latest_rss_report.get("Path") else None,
                        ],
                        "note": "Freshness is derived from current report and polling timestamps." if baseline_hash_status not in ("empty", "unavailable") else "Baseline hash IOC coverage is not available yet.",
                    },
                    {
                        "label": "Host Detections",
                        "title": "Local detection evidence",
                        "copy": "Tripwire and host IOC scanning show whether this PC has recent local evidence worth reviewing.",
                        "tone": "critical" if top_tripwire_alert else "report",
                        "items": [
                            {"label": "Latest tripwire check", "value": pretty_time(tripwire_report_time or "Missing")},
                            {"label": "Latest tripwire baseline", "value": pretty_time(baseline_time or "Missing")},
                            {"label": "Drift/change evidence", "value": drift_evidence},
                            {"label": "Latest host IOC scan", "value": pretty_time(ioc_report_time or "Missing")},
                            {"label": "Observed posture changes", "value": latest_tripwire_posture_summary.get("observed_posture_change_count", "Unknown") if latest_tripwire_posture_summary else "Unknown"},
                            {"label": "Expected operational changes", "value": latest_tripwire_posture_summary.get("expected_operational_change_count", "Unknown") if latest_tripwire_posture_summary else "Unknown"},
                            {"label": "Accepted posture changes", "value": latest_tripwire_posture_summary.get("accepted_posture_change_count", "Unknown") if latest_tripwire_posture_summary else "Unknown"},
                            {"label": "Needs review", "value": latest_tripwire_posture_summary.get("posture_review_count", "Unknown") if latest_tripwire_posture_summary else "Unknown"},
                            {"label": "Response required", "value": latest_tripwire_posture_summary.get("response_required_count", "Unknown") if latest_tripwire_posture_summary else "Unknown"},
                            {"label": "Guardrail protected", "value": latest_tripwire_posture_summary.get("guardrail_protected_count", "Unknown") if latest_tripwire_posture_summary else "Unknown"},
                            {"label": "Accepted registry", "value": latest_tripwire_posture_summary.get("accepted_drift_registry_status", "Unknown") if latest_tripwire_posture_summary else "Unknown"},
                        ],
                        "links": [
                            {"label": "Open latest tripwire report", "href": f"/report?path={urllib.parse.quote(str(latest_tripwire_report.get('Path') or ''), safe='')}"} if latest_tripwire_report.get("Path") else None,
                            {"label": "Open latest IOC report", "href": f"/report?path={urllib.parse.quote(str(latest_ioc_report.get('Path') or ''), safe='')}"} if latest_ioc_report.get("Path") else None,
                        ],
                        "note": (latest_tripwire_posture_summary.get("note") if latest_tripwire_posture_summary else "Tripwire drift summaries describe observed posture changes, not proof of compromise.") + (" Accepted posture changes are recorded when a reviewed change is intentionally trusted." if latest_tripwire_posture_summary and latest_tripwire_posture_summary.get("accepted_posture_change_count", latest_tripwire_posture_summary.get("accepted_drift_count", 0)) else ""),
                    },
                    {
                        "label": "Monitoring Jobs",
                        "title": "Scheduled detection jobs",
                        "copy": "These jobs keep local intelligence and detection evidence current for this PC.",
                        "tone": "warning" if attention_job_names else "calm",
                        "items": [
                            {"label": "Healthy jobs", "value": len(healthy_job_names)},
                            {"label": "Jobs needing attention", "value": len(attention_job_names)},
                            {"label": "Detection jobs tracked", "value": len(detect_task_names)},
                            {"label": "Job health", "value": "Attention needed" if attention_job_names else "Healthy"},
                        ],
                        "links": [
                            {"label": f"Review job: {task.get('Name')}", "href": "#govern-diagnostics"} for task, _ in attention_job_names[:4]
                        ],
                        "note": "Raw task internals remain in diagnostics.",
                    },
                ],
            },
            "respond": {
                "summary": respond_summary,
                "lifecycle": [
                    {"state": "New", "meaning": "Pending alerts waiting for first review."},
                    {"state": "Acknowledged", "meaning": "Seen by an operator. Backend tracking not implemented yet."},
                    {"state": "Investigating", "meaning": "Evidence review in progress. Backend tracking not implemented yet."},
                    {"state": "Resolved", "meaning": "Issue handled and validated. Backend tracking not implemented yet."},
                    {"state": "Archived", "meaning": "Historical alert retained for later reference."},
                ],
                "triage_steps": triage_steps,
            },
            "recover": {},
        },
        "diagnostics": {
            "indicator_stats": indicators,
            "paths": {
                "runtime_root": str(config.runtime_root),
                "data_root": str(config.data_root),
                "state_db_path": str(config.state_db_path),
                "indicator_export_path": str(config.indicator_export_path),
                "alert_inbox_path": str(config.alert_inbox_path),
                "alert_archive_path": str(config.alert_archive_path),
            },
        },
        "metadata": status.get("Metadata", {}),
    }

    _assert_status_badge_rendering()
    _assert_recommended_response_priority(model["recommended_responses"])
    _assert_recovery_readiness_output(model["recovery_readiness"])
    _assert_protection_control_sorting(model["protection_controls"]["sorted"])
    model["csf_sections"]["detect"]["subcards"] = [
        {**card, "links": [link for link in (card.get("links") or []) if link]}
        for card in model["csf_sections"]["detect"]["subcards"]
    ]
    return model


FUNCTION_ROUTE_ORDER = [
    ("govern", "/govern", "Govern"),
    ("identify", "/identify", "Identify"),
    ("protect", "/protect", "Protect"),
    ("detect", "/detect", "Detect"),
    ("respond", "/respond", "Respond"),
    ("recover", "/recover", "Recover"),
]




def coerce_persona_profile(persona: Any) -> Dict[str, Any]:
    if isinstance(persona, dict):
        persona_id = str(persona.get("persona_id") or "user").strip().lower() or "user"
        fallback = DEFAULT_PERSONA_PROFILES.get(persona_id, DEFAULT_PERSONA_PROFILES["user"])
        return normalize_persona_profile(persona_id, persona, fallback)
    persona_id = str(persona or "user").strip().lower() or "user"
    fallback = DEFAULT_PERSONA_PROFILES.get(persona_id, DEFAULT_PERSONA_PROFILES["user"])
    return normalize_persona_profile(persona_id, fallback, fallback)


def persona_label(persona: Any) -> str:
    return str(coerce_persona_profile(persona).get("display_name") or "Home User")


def persona_allows_reports(persona: Any) -> bool:
    return persona_show_reports(coerce_persona_profile(persona))


def persona_allows_diagnostics(persona: Any) -> bool:
    return persona_show_diagnostics(coerce_persona_profile(persona))


def simplify_for_home(persona: Any, technical_text: str, plain_text: str) -> str:
    return simplify_for_persona(coerce_persona_profile(persona), technical_text, plain_text)


def render_primary_nav(current_path: str, *, persona_profile: Dict[str, Any], show_technical: bool = False) -> str:
    links = [f'<a class="btn{" active" if current_path == "/" else ""}" href="/">Dashboard</a>']
    for _, href, label in FUNCTION_ROUTE_ORDER:
        if persona_allows_route(persona_profile, href):
            links.append(f'<a class="btn{" active" if current_path == href else ""}" href="{href}">{esc(label)}</a>')
    if persona_show_reports(persona_profile) and persona_allows_route(persona_profile, "/reports"):
        links.append(f'<a class="btn{" active" if current_path == "/reports" else ""}" href="/reports">Reports</a>')
    if show_technical and persona_show_diagnostics(persona_profile) and persona_allows_route(persona_profile, "/diagnostics"):
        links.append(f'<a class="btn{" active" if current_path == "/diagnostics" else ""}" href="/diagnostics">Diagnostics</a>')
    return "".join(links)


def render_page_shell(model: Dict[str, Any], current_path: str, title: str, lede: str, body_html: str, *, show_technical_nav: bool = False) -> str:
    flash = f'<div class="flash">{esc(model["app"]["message"])}</div>' if model["app"]["message"] else ""
    persona_id = str((model.get("app") or {}).get("ui_persona") or "user")
    persona_profile = coerce_persona_profile((model.get("app") or {}).get("persona_profile") or {"persona_id": persona_id})
    available_personas = (model.get("app") or {}).get("available_personas") or [persona_profile]
    persona_options = "".join(
        f'<option value="{esc(str(option.get("persona_id") or "user"))}"{" selected" if str(option.get("persona_id") or "user") == persona_id else ""}>{esc(option.get("display_name") or option.get("persona_id") or "Home User")}</option>'
        for option in available_personas
    )
    mood = dashboard_mood(model)
    tone = "ok" if mood["tone"] == "calm" else ("medium" if mood["tone"] == "warning" else "high")
    body = f"""
{flash}
<section class="hero">
  <div class="hero-main mood-{esc(mood['mood_class'])}">
    <div class="page-topbar">
      <div class="brand-mark"><span class="brand-dot"></span>PC Care &amp; Security</div>
      {render_status_badge(mood['tag'], tone)}
    </div>
    <div class="kicker">{esc(title)}</div>
    <h1>{esc(title if current_path != '/' else mood['headline'])}</h1>
    <p class="lede">{esc(lede if current_path != '/' else mood['subtext'])}</p>
    <div class="hero-actions">
      <a class="btn primary" href="{esc(next_best_action(model)['href'])}">{esc(next_best_action(model)['label'])}</a>
      <a class="btn" href="/detect">Review what changed</a>
    </div>
    <div class="hero-meta">
      <span>Current view: {esc(persona_label(persona_profile))}</span>
      <span>Protection score: {esc((model.get('protection_controls') or {}).get('score'))}/100</span>
      <span>Pending alerts: {esc(len((model.get('alerts') or {}).get('pending', [])))}</span>
    </div>
  </div>
  <div class="panel stack">
    <div class="kicker">Navigation</div>
    <div class="subnav">{render_primary_nav(current_path, persona_profile=persona_profile, show_technical=show_technical_nav)}</div>
    <form method="post" action="/set-ui-persona" class="task-actions">
      <label class="mini" for="ui_persona">View</label>
      <input type="hidden" name="return_to" value="{esc(current_path)}">
      <select id="ui_persona" name="persona_id" class="btn" style="padding-right:30px;">{persona_options}</select>
      <button class="btn" type="submit">Apply</button>
    </form>
    <div class="mini">{esc("Choose how much detail you want to see. Extra records stay tucked away unless your view asks for them." if not persona_show_diagnostics(persona_profile) else "Choose how much detail you want to see. Reports and diagnostics stay out of the way unless your view asks for them.")}</div>
  </div>
</section>
{body_html}
"""
    return html_page("Codex Monitor UI", body)



def build_detection_snapshot_detail(config: AppConfig, snapshot: Dict[str, Any]) -> Dict[str, Any]:
    latest_ioc_path = Path(str((((snapshot.get("status") or {}).get("LatestArtifacts") or {}).get("LatestIocReport") or {}).get("Path") or ""))
    if not latest_ioc_path.exists():
        return {"available": False, "reason": "No IOC report is available yet."}
    try:
        payload = parse_json(latest_ioc_path)
    except Exception as exc:
        return {"available": False, "reason": f"Latest IOC report could not be parsed: {exc}"}
    metadata = payload.get("Metadata") or {}
    snapshot_id = str(metadata.get("CurrentSnapshotId") or "").strip()
    if not snapshot_id:
        return {"available": False, "reason": "The latest IOC report does not declare a current evidence snapshot ID.", "report_path": str(latest_ioc_path)}
    if not config.state_db_path.exists():
        return {"available": False, "reason": "The SQLite state database does not exist.", "snapshot_id": snapshot_id, "report_path": str(latest_ioc_path)}
    connection = sqlite3.connect(str(config.state_db_path))
    connection.row_factory = sqlite3.Row
    try:
        row = connection.execute(
            "SELECT snapshot_id, snapshot_type, created_at, host, source_json_path, source_markdown_path, collector_version, trust_label FROM evidence_snapshots WHERE snapshot_id = ?",
            (snapshot_id,),
        ).fetchone()
        if row is None:
            return {"available": False, "reason": "The latest IOC report references a snapshot that is not indexed in SQLite.", "snapshot_id": snapshot_id, "report_path": str(latest_ioc_path)}
        counts = {}
        for table_name in (
            "network_connection_observations",
            "dns_cache_observations",
            "powershell_event_observations",
            "windows_event_observations",
            "registry_observations",
            "service_observations",
            "scheduled_task_observations",
            "autorun_observations",
            "process_observations",
            "file_observations",
        ):
            counts[table_name] = connection.execute(f"SELECT COUNT(*) FROM {table_name} WHERE snapshot_id = ?", (snapshot_id,)).fetchone()[0]
        return {
            "available": True,
            "snapshot": dict(row),
            "counts": counts,
            "report_path": str(latest_ioc_path),
            "hash_coverage": payload.get("HashCoverage") or {},
            "match_count": payload.get("MatchCount"),
            "match_interpretation": payload.get("MatchInterpretation") or "",
        }
    finally:
        connection.close()


def render_function_cards(model: Dict[str, Any], snapshot: Dict[str, Any]) -> str:
    status = snapshot["status"]
    local_pc = model["this_pc"]["identity"]
    protection = model["protection_controls"]
    detect = model["csf_sections"]["detect"]
    respond = model["csf_sections"]["respond"]
    recovery = model["recovery_readiness"]
    findings = model["csf_sections"]["govern"]["findings"]
    persona = (model.get("app") or {}).get("persona_profile") or (model.get("app") or {}).get("ui_persona")
    cards = [
        ("govern", "/govern", "How this care plan is running", f'{len(findings)} item(s) worth reviewing. Overall status: {status["Metadata"]["OverallStatus"]}.', f'Jobs needing review: {model["task_job_health"]["attention_tasks"]}'),
        ("identify", "/identify", "What makes up this PC", f'{local_pc["WindowsEdition"]} / {local_pc["WindowsVersionBuild"]}', f'Baseline saved: {pretty_time(local_pc["BaselineTimestamp"])}'),
        ("protect", "/protect", "Core protections", f'Protection score {protection["score"]}/100.', f'{len(protection["actionable"])} item(s) need care'),
        ("detect", "/detect", "What the app is watching", detect["summary"], detect["hash_coverage_line"]),
        ("respond", "/respond", "How issues are handled", respond["summary"], f'Pending alerts: {len(model["alerts"]["pending"])}'),
        ("recover", "/recover", "How ready you are to recover", f'Recovery readiness is {recovery["Overall"]}.', recovery["Recommendations"][0] if recovery["Recommendations"] else ""),
    ]
    return "".join(
        f'<a class="focus-card report" href="{esc(route)}"><div class="focus-label">{esc(friendly_function_label(section, persona))}</div><div class="focus-title">{esc(title)}</div><div class="focus-copy">{esc(copy)}</div><div class="focus-meta">{esc(meta)}</div></a>'
        for section, route, title, copy, meta in cards
    )


def render_dashboard(config: AppConfig, snapshot: Dict[str, Any], message: str = "") -> str:
    model = build_dashboard_model(config, snapshot, message)
    status = snapshot["status"]
    persona_id = config.ui_persona
    mood = dashboard_mood(model)
    latest_artifacts = status.get("LatestArtifacts") or {}
    latest_ioc = latest_artifacts.get("LatestIocReport") or {}
    latest_tripwire = latest_artifacts.get("LatestTripwireReport") or {}
    latest_rss = latest_artifacts.get("LatestThreatRssReport") or {}
    top_pending = model["alerts"]["pending"][0] if model["alerts"]["pending"] else None
    top_report = model["reports"]["top"]
    strip = render_status_strip([
        {"label": "Overall wellbeing", "value": mood["tag"]},
        {"label": "Protection", "value": f'{model["protection_controls"]["score"]}/100'},
        {"label": "Last scan", "value": pretty_time(latest_ioc.get("LastWriteTimeUtc") or latest_tripwire.get("LastWriteTimeUtc") or "")},
        {"label": "Updates", "value": pretty_time(status["State"].get("ThreatRssLastRunUtc") or latest_rss.get("LastWriteTimeUtc") or "")},
    ])
    looks_good = []
    if model["protection_controls"]["score"] >= 80:
        looks_good.append(("Protection is on", "Your main protection checks are in good shape right now.", "/protect"))
    if not model["alerts"]["pending"]:
        looks_good.append(("No active warnings are waiting", "There are no pending alerts open for this PC right now.", "/respond"))
    if parse_display_datetime(model["this_pc"]["identity"].get("BaselineTimestamp")):
        looks_good.append(("Recovery baseline is available", "A saved baseline exists so later checks can compare against a known-good point.", "/recover"))
    if model["task_job_health"]["attention_tasks"] == 0:
        looks_good.append(("Everything important is running", "The scheduled jobs that keep this PC watched are operational.", "/govern"))
    if not looks_good:
        looks_good.append(("Care is in progress", "The app still has useful coverage, even when a few items need review.", "/govern"))
    needs_care_tiles = []
    for item in model["recommended_responses"][:4]:
        tone = "serious" if item.get("tone") == "high" else ("care" if item.get("tone") == "medium" else "good")
        href = next_best_action({"recommended_responses": [item]}).get("href", "/protect")
        needs_care_tiles.append(render_care_tile(str(item.get("title") or "Needs care"), str(item.get("summary") or item.get("detail") or ""), tone=tone, href=href))
    recent_activity = render_recent_activity([
        {"title": "Threat checks", "body": f'Latest indicator check: {pretty_time(latest_ioc.get("LastWriteTimeUtc") or "")}.', "meta": "Detect"},
        {"title": "Change watch", "body": f'Latest tripwire check: {pretty_time(latest_tripwire.get("LastWriteTimeUtc") or "")}.', "meta": "Detect"},
        {"title": "Threat feeds", "body": f'Feed refresh: {pretty_time(status["State"].get("ThreatRssLastRunUtc") or latest_rss.get("LastWriteTimeUtc") or "")}.', "meta": "Detect"},
        {"title": "Latest alert", "body": (top_pending.get("title") if top_pending else "No pending alerts are waiting for review."), "meta": "Respond"},
        {"title": "Saved evidence", "body": (top_report.get("name") if top_report else "No recent report is available yet."), "meta": "Reports"},
    ])
    body = f"""
<section class="panel stack">
  <div class="kicker">Today</div>
  <h2>{esc(mood['headline'])}</h2>
  <div class="mini">{esc(mood['subtext'])}</div>
  {strip}
</section>
<section class="grid two">
  <div class="panel stack">
    <div class="kicker">What looks good</div>
    <h2>What is helping your PC stay steady</h2>
    <div class="care-list">{''.join(render_care_tile(t, b, tone='good', href=h) for t, b, h in looks_good[:4])}</div>
  </div>
  <div class="panel stack">
    <div class="kicker">What needs care</div>
    <h2>Top items to review next</h2>
    <div class="care-list">{''.join(needs_care_tiles) or render_care_tile('Nothing urgent needs care', 'The most important checks look steady right now.', tone='good', href='/protect')}</div>
  </div>
</section>
<section class="grid two">
  <div class="panel stack">
    <div class="kicker">What changed</div>
    <h2>Recent activity</h2>
    {recent_activity}
  </div>
  <div class="panel stack">
    <div class="kicker">Recovery</div>
    <h2>Recovery readiness</h2>
    <div class="focus-card {'calm' if model['recovery_readiness']['Overall'] in ('Moderate', 'Available') else 'warning'}">
      <div class="focus-label">Preparedness</div>
      <div class="focus-title">{esc('Recovery baseline is available' if parse_display_datetime(model['this_pc']['identity'].get('BaselineTimestamp')) else 'Recovery needs more setup')}</div>
      <div class="focus-copy">{esc(model['recovery_readiness']['Recommendations'][0] if model['recovery_readiness']['Recommendations'] else 'Recovery details are available when you need them.')}</div>
      <div class="focus-meta">Overall readiness: {esc(model['recovery_readiness']['Overall'])}</div>
    </div>
    <div class="task-actions"><a class="btn" href="/recover">Improve readiness</a></div>
  </div>
</section>
<section class="panel stack">
  <div class="kicker">Care journey</div>
  <h2>{esc('NIST care journey' if persona_allows_technical_detail(persona_id) else 'How this app looks after your PC')}</h2>
  <div class="grid three">{render_function_cards(model, snapshot)}</div>
</section>
<section class="grid two">
  <div class="panel stack">
    <div class="kicker">Protection</div>
    <h2>Where to go next</h2>
    <div class="task-actions"><a class="btn primary" href="{esc(next_best_action(model)['href'])}">{esc(next_best_action(model)['label'])}</a>{(f'<a class="btn" href="/reports">Open records</a>' if persona_show_reports(coerce_persona_profile(persona_id)) else '')}</div>
    <div class="mini">{esc("Saved reports remain available when you want more detail." if persona_show_reports(coerce_persona_profile(persona_id)) else "This overview stays simple so you can focus on what needs care now.")}</div>
  </div>
  <div class="panel stack">
    <div class="kicker">Reports</div>
    <h2>Clean records of care</h2>
    <div class="focus-card report">
      <div class="focus-label">Latest saved record</div>
      <div class="focus-title">{esc(top_report.get('name') if top_report else 'No recent report yet')}</div>
      <div class="focus-copy">{esc(top_report.get('report_type') if top_report else 'Reports appear here after checks run.')}</div>
      <div class="focus-meta">{esc(pretty_time((top_report or {}).get('collection_time') or ''))}</div>
    </div>
  </div>
</section>
"""
    return render_page_shell(model, "/", simplify_for_home(persona_id, "PC care overview", "Your PC care overview"), simplify_for_home(persona_id, "A calm overview of how this PC is doing, what changed, and what needs care next.", "See how your PC is doing today and what needs care next."), body, show_technical_nav=persona_allows_diagnostics(persona_id))


def render_govern_page(config: AppConfig, snapshot: Dict[str, Any], message: str = "") -> str:
    model = build_dashboard_model(config, snapshot, message)
    persona_id = config.ui_persona
    status = snapshot["status"]
    tasks_by_name = model["task_job_health"]["by_name"]
    task_markup = "".join(render_task(tasks_by_name[name]) for name in model["task_job_health"]["groups"]["govern"] if name in tasks_by_name)
    finding_markup = "".join(f'<div class="finding {esc((finding.get("Severity") or "").lower())}"><strong>[{esc(finding.get("Severity"))}]</strong> {esc(finding.get("Message"))}</div>' for finding in model["csf_sections"]["govern"]["findings"]) or '<div class="finding">No health findings.</div>'
    body = f"""
<section class="grid two" style="margin-top:18px">
  <div class="panel stack">
    <div class="kicker">Govern</div>
    <h2>Care plan health</h2>
    {render_status_badge(status['Metadata']['OverallStatus'], status['Metadata']['OverallStatus'])}
    <div class="mini">Review whether the care system for this PC is healthy, current, and ready to keep watching in the background.</div>
    {finding_markup}
  </div>
  <div class="panel stack">
    <div class="kicker">Govern</div>
    <h2>How the background care is running</h2>
    <div class="cards">
      {render_metric_card({"label": "Healthy jobs", "value": f"{model['task_job_health']['healthy_tasks']}/{len(model['task_job_health']['all'])}"})}
      {render_metric_card({"label": "Jobs needing review", "value": model['task_job_health']['attention_tasks']})}
    </div>
    {('<div class="task-actions"><a class="btn" href="/diagnostics">Open diagnostics</a></div>' if persona_show_diagnostics(coerce_persona_profile(persona_id)) else '')}
  </div>
</section>
<section class="panel stack" style="margin-top:18px">
  <div class="kicker">Govern</div>
  <h2>Protection jobs</h2>
  {task_markup}
</section>
"""
    return render_page_shell(model, "/govern", "Govern", simplify_for_home(persona_id, "Choose how this PC care plan runs and review whether the local protection jobs are succeeding.", "Choose how hands-on this care plan should be and confirm the monitor is running well."), body, show_technical_nav=True)


def render_identify_page(config: AppConfig, snapshot: Dict[str, Any], message: str = "") -> str:
    model = build_dashboard_model(config, snapshot, message)
    persona_id = config.ui_persona
    local_pc = model["this_pc"]["identity"]
    body = f"""
<section class="panel stack" style="margin-top:18px">
  <div class="kicker">Identify</div>
  <h2>This PC</h2>
  <div class="focus-card report">
    <div class="focus-label">Local host context</div>
    <div class="focus-title">{esc(model["this_pc"]["focus"]["title"])}</div>
    <div class="focus-copy">{esc(model["this_pc"]["focus"]["copy"])}</div>
    <div class="focus-meta">{esc(model["this_pc"]["focus"]["meta"])}</div>
  </div>
  <dl class="kv">
    <dt>Hostname</dt><dd>{esc(local_pc["Hostname"])}</dd>
    <dt>Manufacturer</dt><dd>{esc(local_pc["Manufacturer"])}</dd>
    <dt>Model</dt><dd>{esc(local_pc["Model"])}</dd>
    <dt>Windows edition</dt><dd>{esc(local_pc["WindowsEdition"])}</dd>
    <dt>Windows version</dt><dd>{esc(local_pc["WindowsVersion"])}</dd>
    <dt>Windows build</dt><dd>{esc(local_pc["WindowsBuild"])}</dd>
    <dt>Current user</dt><dd>{esc(local_pc["CurrentUser"])}</dd>
    <dt>Baseline timestamp</dt><dd>{esc(pretty_time(local_pc["BaselineTimestamp"]))}</dd>
    <dt>Baseline scope</dt><dd>{esc(local_pc["BaselineScope"])}</dd>
  </dl>
  <div class="cards">{''.join(render_metric_card(metric) for metric in model["this_pc"]["asset_scope_metrics"])}</div>
  <div class="cards">{''.join(render_metric_card(metric) for metric in model["this_pc"]["evidence_metrics"])}</div>
</section>
"""
    return render_page_shell(model, "/identify", "Identify", simplify_for_home(persona_id, "See the known environment of this PC, its baseline scope, and the parts of the system that are being watched.", "See what makes up this PC and what the app is watching."), body, show_technical_nav=True)


def render_protect_page(config: AppConfig, snapshot: Dict[str, Any], message: str = "") -> str:
    model = build_dashboard_model(config, snapshot, message)
    persona_id = config.ui_persona
    protection = model["protection_controls"]
    protection_score_markup = render_status_badge(f"Score {protection['score']}/100", protection_score_tone(protection["score"]))
    protection_options = "".join(f'<option value="{esc(profile.get("Id"))}"{" selected" if profile.get("Id") == protection["profile"].get("Id") else ""}>{esc(profile.get("Name"))}</option>' for profile in protection["profiles"])
    actionable_control_markup = "".join(render_protect_attention_control(control) for control in protection["actionable"]) or '<div class="finding">No failed or partial protection controls.</div>'
    passing_control_rows = "".join(render_protection_control_row(control) for control in protection["passing"]) or "<tr><td colspan='3' class='mini'>No passing protection controls.</td></tr>"
    body = f"""
<section class="panel stack" style="margin-top:18px">
  <div class="kicker">Protect</div>
  <div class="task-head">
    <div>
      <h2>Protective posture</h2>
      <div class="mini">Choose the protection style this PC should follow, then review what already looks good and what still needs care.</div>
    </div>
    <div class="task-actions">
      {protection_score_markup}
      <form method="post" action="/set-protection-profile">
        <input type="hidden" name="return_to" value="/protect">
        <label class="mini" for="protection_profile">Profile</label>
        <select id="protection_profile" name="profile_id" class="btn" style="padding-right:30px; margin-left:8px;">{protection_options}</select>
        <button class="btn primary" type="submit">Apply profile</button>
      </form>
    </div>
  </div>
  <div class="focus-card report">
    <div class="focus-label">Active template</div>
    <div class="focus-title">{esc(protection["profile"].get("Name") or "Unknown profile")}</div>
    <div class="focus-copy">{esc(protection["profile"].get("Description") or "No description available.")}</div>
    <div class="focus-meta">{esc(protection["profile"].get("Source") or "")}</div>
  </div>
  <div class="stack"><h3>Controls needing planning</h3>{actionable_control_markup}</div>
  <div class="panel stack" style="background: var(--panel-soft);">
    <h3>Passing controls</h3>
    <table><thead><tr><th>Control</th><th>Current</th><th>Status</th></tr></thead><tbody>{passing_control_rows}</tbody></table>
  </div>
</section>
"""
    return render_page_shell(model, "/protect", "Protect", simplify_for_home(persona_id, "Review the protections that keep this PC guarded and the care items that still need planning, without changing Windows settings from this page.", "Review the protections this PC should have and what still needs care."), body, show_technical_nav=True)


def render_detect_page(config: AppConfig, snapshot: Dict[str, Any], message: str = "") -> str:
    model = build_dashboard_model(config, snapshot, message)
    persona_id = config.ui_persona
    detect = model["csf_sections"]["detect"]
    report_rows = "".join(render_report_row(item) for item in model["reports"]["recent"]) or "<tr><td colspan='4' class='mini'>No reports found.</td></tr>"
    ingest_rows = "".join(f"<tr><td>{esc(run['source_name'])}</td><td>{esc(run['status'])}</td><td>{esc(run['indicator_count'])}</td><td>{esc(pretty_time(run['started_at']))}</td></tr>" for run in snapshot["indicators"]["ingest_runs"]) or "<tr><td colspan='4' class='mini'>No ingest runs found.</td></tr>"
    detect_cards_markup = "".join(render_detect_focus_card(card) for card in detect["subcards"])
    evidence_link = '<div class="task-actions"><a class="btn" href="/detect/evidence-snapshot">Open evidence snapshot details</a></div>' if persona_show_evidence_links(coerce_persona_profile(persona_id)) else ""
    body = f"""
<section class="panel stack" style="margin-top:18px">
  <div class="kicker">Detect</div>
  <h2>What the app is watching</h2>
  <div class="mini">{esc(detect["summary"])}</div>
  <div class="mini">{esc(detect["hash_coverage_line"])}</div>
  {evidence_link}
  <div class="grid three">{detect_cards_markup}</div>
</section>
<section class="panel stack" style="margin-top:18px">
  <div class="kicker">Detect</div>
  <h2>Ingest Runs</h2>
  <table><thead><tr><th>Source</th><th>Status</th><th>Indicators</th><th>Started</th></tr></thead><tbody>{ingest_rows}</tbody></table>
</section>
<section class="panel stack" style="margin-top:18px">
  <div class="kicker">Detect</div>
  <h2>Recent Reports</h2>
  <table><thead><tr><th>Report</th><th>Type</th><th>Collected</th><th>Summary</th></tr></thead><tbody>{report_rows}</tbody></table>
</section>
"""
    return render_page_shell(model, "/detect", "Detect", simplify_for_home(persona_id, "See what the app is watching, whether anything changed, and how current your threat checks are.", "See what the app is watching and whether anything needs a closer look."), body, show_technical_nav=True)


def render_detect_evidence_snapshot_page(config: AppConfig, snapshot: Dict[str, Any], message: str = "") -> str:
    model = build_dashboard_model(config, snapshot, message)
    persona_id = config.ui_persona
    detail = build_detection_snapshot_detail(config, snapshot)
    if not detail.get("available"):
        body = f'<section class="panel stack" style="margin-top:18px"><div class="kicker">Detect</div><h2>Evidence Snapshot</h2><div class="finding">{esc(detail.get("reason") or "Evidence snapshot details are unavailable.")}</div><div class="task-actions"><a class="btn" href="/detect">Back to Detect</a></div></section>'
    else:
        snapshot_row = detail["snapshot"]
        counts_rows = "".join(f"<tr><td>{esc(name)}</td><td>{esc(value)}</td></tr>" for name, value in detail["counts"].items())
        coverage_rows = "".join(f"<tr><td>{esc(key)}</td><td>{esc(value)}</td></tr>" for key, value in (detail.get("hash_coverage") or {}).items()) or "<tr><td colspan='2' class='mini'>No hash coverage details available.</td></tr>"
        body = f"""
<section class="grid two" style="margin-top:18px">
  <div class="panel stack">
    <div class="kicker">Detect</div>
    <h2>Evidence Snapshot</h2>
    <dl class="kv">
      <dt>Snapshot ID</dt><dd>{esc(snapshot_row.get("snapshot_id"))}</dd>
      <dt>Snapshot type</dt><dd>{esc(snapshot_row.get("snapshot_type"))}</dd>
      <dt>Created</dt><dd>{esc(pretty_time(snapshot_row.get("created_at")))}</dd>
      <dt>Host</dt><dd>{esc(snapshot_row.get("host") or "Unknown")}</dd>
      <dt>Collector</dt><dd>{esc(snapshot_row.get("collector_version") or "Unknown")}</dd>
      <dt>Trust label</dt><dd>{esc(snapshot_row.get("trust_label") or "Unknown")}</dd>
      <dt>Latest report</dt><dd><a href="/report?path={urllib.parse.quote(str(detail['report_path']), safe='')}">{esc(Path(detail['report_path']).name)}</a></dd>
    </dl>
    <div class="mini">{esc(detail.get("match_interpretation") or "No match interpretation available.")}</div>
  </div>
  <div class="panel stack">
    <div class="kicker">Detect</div>
    <h2>Snapshot counts</h2>
    <table><thead><tr><th>Observation table</th><th>Count</th></tr></thead><tbody>{counts_rows}</tbody></table>
  </div>
</section>
<section class="panel stack" style="margin-top:18px">
  <div class="kicker">Detect</div>
  <h2>Hash coverage</h2>
  <table><thead><tr><th>Field</th><th>Value</th></tr></thead><tbody>{coverage_rows}</tbody></table>
</section>
"""
    return render_page_shell(model, "/detect/evidence-snapshot", "Detect evidence snapshot", simplify_for_home(persona_id, "This page shows the latest indexed local evidence snapshot and the observation counts behind snapshot-aware IOC matching.", "This page shows the detailed evidence collected for the latest detection check."), body, show_technical_nav=persona_allows_diagnostics(persona_id))


def render_respond_page(config: AppConfig, snapshot: Dict[str, Any], message: str = "") -> str:
    model = build_dashboard_model(config, snapshot, message)
    persona_id = config.ui_persona
    respond = model["csf_sections"]["respond"]
    tasks_by_name = model["task_job_health"]["by_name"]
    notifier_task = tasks_by_name.get("Codex Alert Notifier", {})
    notifier_status = classify_task_result(notifier_task) if notifier_task else {"label": "Unknown", "tone": "medium", "message": "Alert delivery state is unavailable."}
    pending_rows = "".join(render_alert_row(item, lifecycle_state="New", show_actions=True) for item in model["alerts"]["pending"][:20]) or "<tr><td colspan='5' class='mini'>No pending alerts.</td></tr>"
    archive_rows = "".join(render_alert_row(item, lifecycle_state="Archived", show_actions=False) for item in model["alerts"]["archived"][:20]) or "<tr><td colspan='5' class='mini'>No archived alerts.</td></tr>"
    triage_steps = "".join(f"<li>{esc(step)}</li>" for step in respond["triage_steps"])
    lifecycle_rows = "".join(f"<tr><td>{render_status_badge(item['state'], 'info' if item['state'] != 'Archived' else 'ok')}</td><td>{esc(item['meaning'])}</td></tr>" for item in respond["lifecycle"])
    body = f"""
<section class="grid two" style="margin-top:18px">
  <div class="panel stack">
    <div class="kicker">Respond</div>
    <h2>Guided issue resolution</h2>
    <div class="mini">{esc(respond['summary'])}</div>
    <div class="focus-card {'warning' if model['alerts']['pending'] else 'calm'}">
      <div class="focus-label">Response summary</div>
      <div class="focus-title">{esc('Pending alerts need review' if model['alerts']['pending'] else 'No active incidents open')}</div>
      <div class="focus-copy">{esc(respond['summary'])}</div>
      <div class="focus-meta">Notifier status: {esc(notifier_status['label'])} • {esc(notifier_status['message'])}</div>
    </div>
    <div class="focus-card report"><div class="focus-label">Suggested triage</div><div class="focus-copy"><ul style="margin:0; padding-left:18px;">{triage_steps}</ul></div></div>
  </div>
  <div class="panel stack">
    <div class="kicker">Respond</div>
    <h2>Pending Alerts</h2>
    <table><thead><tr><th>Severity</th><th>Alert</th><th>State</th><th>Count</th><th>Collected</th></tr></thead><tbody>{pending_rows}</tbody></table>
  </div>
</section>
<section class="grid two" style="margin-top:18px">
  <div class="panel stack">
    <div class="kicker">Respond</div>
    <h2>Archived Alerts</h2>
    <table><thead><tr><th>Severity</th><th>Alert</th><th>State</th><th>Count</th><th>Collected</th></tr></thead><tbody>{archive_rows}</tbody></table>
  </div>
  <div class="panel stack">
    <div class="kicker">Respond</div>
    <h2>Alert lifecycle</h2>
    <div class="mini">Pending alerts are treated as New. Archived alerts are treated as Archived until backend workflow state is implemented.</div>
    <table><thead><tr><th>State</th><th>Meaning</th></tr></thead><tbody>{lifecycle_rows}</tbody></table>
  </div>
</section>
"""
    return render_page_shell(model, "/respond", "Respond", simplify_for_home(persona_id, "Use the guided issue-resolution view when this PC has alerts, then preserve the evidence and review history on demand.", "If something needs attention, this is where the app helps you handle it."), body, show_technical_nav=True)


def render_recover_page(config: AppConfig, snapshot: Dict[str, Any], message: str = "") -> str:
    model = build_dashboard_model(config, snapshot, message)
    persona_id = config.ui_persona
    recovery = model["recovery_readiness"]
    recovery_rows = "".join(f"<tr><td>{esc(label)}</td><td>{esc(entry['Status'])}</td><td>{esc(pretty_time(entry['Value']) if 'Baseline' in label else entry['Value'])}</td><td>{esc(entry['Message'])}</td></tr>" for label, entry in [("Last known-good baseline", recovery["LastKnownGoodBaseline"]), ("Rollback records status", recovery["RollbackRecords"]), ("Restore point status", recovery["RestorePointStatus"]), ("Backup status", recovery["BackupStatus"]), ("Post-remediation validation", recovery["PostRemediationValidation"])])
    recovery_recommendations = "".join(f"<li>{esc(item)}</li>" for item in recovery["Recommendations"])
    return render_page_shell(model, "/recover", "Recover", simplify_for_home(persona_id, "Review whether this PC has enough baseline, rollback, and validation context to recover safely after cleanup or planned changes.", "Review the tools and records that help this PC get back to steady."), render_recovery_card(recovery, recovery_rows, recovery_recommendations), show_technical_nav=True)


def render_reports_page(config: AppConfig, snapshot: Dict[str, Any], message: str = "") -> str:
    model = build_dashboard_model(config, snapshot, message)
    persona_id = config.ui_persona
    report_rows = "".join(render_report_row(item) for item in model["reports"]["recent"]) or "<tr><td colspan='4' class='mini'>No reports found.</td></tr>"
    body = f'<section class="panel stack" style="margin-top:18px"><div class="kicker">Reports</div><h2>Records of care</h2><div class="mini">These JSON and Markdown reports remain the exportable evidence artifacts for this local PC monitor.</div><table><thead><tr><th>Report</th><th>Type</th><th>Collected</th><th>Summary</th></tr></thead><tbody>{report_rows}</tbody></table></section>'
    return render_page_shell(model, "/reports", "Reports", simplify_for_home(persona_id, "Open clean records of what was checked, what changed, and what still needs care.", "Open saved records for more detail about the checks on this PC."), body, show_technical_nav=persona_allows_diagnostics(persona_id))


def render_diagnostics_page(config: AppConfig, snapshot: Dict[str, Any], message: str = "") -> str:
    model = build_dashboard_model(config, snapshot, message)
    indicators = snapshot["indicators"]
    tasks_by_name = model["task_job_health"]["by_name"]
    govern_task_markup = "".join(render_task(tasks_by_name[name]) for name in model["task_job_health"]["groups"]["govern"] if name in tasks_by_name)
    type_rows = "".join(f"<tr><td>{esc(row['type'])}</td><td>{esc(row['count'])}</td></tr>" for row in indicators["by_type"]) or "<tr><td colspan='2' class='mini'>No indicator data.</td></tr>"
    source_rows = "".join(f"<tr><td>{esc(row['source'])}</td><td>{esc(row['count'])}</td></tr>" for row in indicators["by_source"]) or "<tr><td colspan='2' class='mini'>No source data.</td></tr>"
    app_state_rows = "".join(f"<tr><td>{esc(row['namespace'])}</td><td>{esc(row['state_key'])}</td><td>{esc(row['updated_at'])}</td></tr>" for row in indicators["app_state"]) or "<tr><td colspan='3' class='mini'>No app state found.</td></tr>"
    body = f"""
<section class="panel stack" style="margin-top:18px">
  <div class="kicker">Diagnostics</div>
  <h2>All protection jobs</h2>
  <div class="mini">Full task inventory and internals, retained here for technician-style diagnostics.</div>
  {govern_task_markup}
</section>
<section class="grid three" style="margin-top:18px">
  <div class="panel stack"><h2>Indicator Types</h2><table><thead><tr><th>Type</th><th>Count</th></tr></thead><tbody>{type_rows}</tbody></table></div>
  <div class="panel stack"><h2>Indicator Sources</h2><table><thead><tr><th>Source</th><th>Count</th></tr></thead><tbody>{source_rows}</tbody></table></div>
  <div class="panel stack"><h2>SQLite App State</h2><table><thead><tr><th>Namespace</th><th>Key</th><th>Updated</th></tr></thead><tbody>{app_state_rows}</tbody></table></div>
</section>
<section class="panel stack" style="margin-top:18px">
  <h2>Paths</h2>
  <div class="kv">
    <dt>Runtime root</dt><dd>{esc(config.runtime_root)}</dd>
    <dt>Data root</dt><dd>{esc(config.data_root)}</dd>
    <dt>State DB</dt><dd>{esc(config.state_db_path)}</dd>
    <dt>Indicator export</dt><dd>{esc(config.indicator_export_path)}</dd>
    <dt>Pending alerts</dt><dd>{esc(config.alert_inbox_path)}</dd>
    <dt>Archive alerts</dt><dd>{esc(config.alert_archive_path)}</dd>
  </div>
</section>
"""
    return render_page_shell(model, "/diagnostics", "Diagnostics", "Technician pages keep the raw jobs, indicator statistics, and local paths available without weighing down the main dashboard.", body, show_technical_nav=True)


def render_file_detail(title: str, subtitle: str, payload_text: str) -> str:
    body = f"""
<section class="panel stack">
  <div class="kicker">{esc(subtitle)}</div>
  <h1>{esc(title)}</h1>
  <p><a href="/">Back to dashboard</a></p>
  <pre>{esc(payload_text)}</pre>
</section>
"""
    return html_page(title, body)


class CodexUiHandler(BaseHTTPRequestHandler):
    server_version = "CodexMonitorUI/1.0"

    @property
    def app_config(self) -> AppConfig:
        return self.server.app_config  # type: ignore[attr-defined]

    def do_GET(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        params = urllib.parse.parse_qs(parsed.query)

        try:
            if parsed.path == "/":
                message = params.get("message", [""])[0]
                snapshot = build_snapshot(self.app_config)
                return self.respond_html(render_dashboard(self.app_config, snapshot, message))

            if parsed.path == "/govern":
                message = params.get("message", [""])[0]
                snapshot = build_snapshot(self.app_config)
                return self.respond_html(render_govern_page(self.app_config, snapshot, message))

            if parsed.path == "/identify":
                message = params.get("message", [""])[0]
                snapshot = build_snapshot(self.app_config)
                return self.respond_html(render_identify_page(self.app_config, snapshot, message))

            if parsed.path == "/protect":
                message = params.get("message", [""])[0]
                snapshot = build_snapshot(self.app_config)
                return self.respond_html(render_protect_page(self.app_config, snapshot, message))

            if parsed.path == "/detect":
                message = params.get("message", [""])[0]
                snapshot = build_snapshot(self.app_config)
                return self.respond_html(render_detect_page(self.app_config, snapshot, message))

            if parsed.path == "/detect/evidence-snapshot":
                message = params.get("message", [""])[0]
                snapshot = build_snapshot(self.app_config)
                return self.respond_html(render_detect_evidence_snapshot_page(self.app_config, snapshot, message))

            if parsed.path == "/respond":
                message = params.get("message", [""])[0]
                snapshot = build_snapshot(self.app_config)
                return self.respond_html(render_respond_page(self.app_config, snapshot, message))

            if parsed.path == "/recover":
                message = params.get("message", [""])[0]
                snapshot = build_snapshot(self.app_config)
                return self.respond_html(render_recover_page(self.app_config, snapshot, message))

            if parsed.path == "/reports":
                message = params.get("message", [""])[0]
                snapshot = build_snapshot(self.app_config)
                return self.respond_html(render_reports_page(self.app_config, snapshot, message))

            if parsed.path == "/diagnostics":
                message = params.get("message", [""])[0]
                snapshot = build_snapshot(self.app_config)
                return self.respond_html(render_diagnostics_page(self.app_config, snapshot, message))

            if parsed.path == "/alert":
                requested = params.get("path", [""])[0]
                alert_path = safe_path(
                    requested,
                    [self.app_config.alert_inbox_path, self.app_config.alert_archive_path, self.app_config.data_root],
                )
                if alert_path is None or not alert_path.exists():
                    return self.respond_error(HTTPStatus.NOT_FOUND, "Alert file not found.")
                alert_payload = parse_json(alert_path)
                md_path = alert_path.with_suffix(".md")
                text_parts = [json.dumps(alert_payload, indent=2)]
                if md_path.exists():
                    text_parts.append("\n--- markdown companion ---\n")
                    text_parts.append(read_text(md_path))
                return self.respond_html(render_file_detail(alert_path.name, str(alert_path), "\n".join(text_parts)))

            if parsed.path == "/report":
                requested = params.get("path", [""])[0]
                roots = [self.app_config.runtime_root, self.app_config.data_root, self.app_config.repo_root]
                report_path = safe_path(requested, roots)
                if report_path is None or not report_path.exists():
                    return self.respond_error(HTTPStatus.NOT_FOUND, "Report file not found.")
                if report_path.suffix.lower() == ".json":
                    payload_text = json.dumps(parse_json(report_path), indent=2)
                else:
                    payload_text = read_text(report_path)
                return self.respond_html(render_file_detail(report_path.name, str(report_path), payload_text))

            if parsed.path == "/api/snapshot":
                return self.respond_json(build_snapshot(self.app_config))

            return self.respond_error(HTTPStatus.NOT_FOUND, "Route not found.")
        except (BrokenPipeError, ConnectionAbortedError, ConnectionResetError):
            return
        except Exception as exc:
            return self.respond_error(HTTPStatus.INTERNAL_SERVER_ERROR, str(exc))

    def do_POST(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        try:
            length = int(self.headers.get("Content-Length", "0"))
            body = self.rfile.read(length).decode("utf-8")
            payload = urllib.parse.parse_qs(body)
            return_to = payload.get("return_to", [""])[0].strip() or "/"
            allowed_return_routes = {
                "/",
                "/govern",
                "/identify",
                "/protect",
                "/detect",
                "/detect/evidence-snapshot",
                "/respond",
                "/recover",
                "/reports",
                "/diagnostics",
            }
            if return_to not in allowed_return_routes:
                return_to = "/"

            if parsed.path == "/run-task":
                task_name = payload.get("task_name", [""])[0]
                if task_name not in TASK_NAMES:
                    raise RuntimeError("Unknown task requested.")
                result = run_task(task_name, self.app_config)
                return self.redirect("/?message=" + urllib.parse.quote(result))

            if parsed.path == "/run-tripwire-baseline":
                result = run_tripwire_baseline(self.app_config)
                return self.redirect("/?message=" + urllib.parse.quote(result))

            if parsed.path == "/set-protection-profile":
                profile_id = payload.get("profile_id", [""])[0].strip()
                if not profile_id:
                    raise RuntimeError("No protection profile was provided.")
                result = set_protection_profile(self.app_config, profile_id)
                return self.redirect(return_to + "?message=" + urllib.parse.quote(result))

            if parsed.path == "/set-ui-persona":
                persona_id = payload.get("persona_id", [""])[0].strip()
                if not persona_id:
                    raise RuntimeError("No UI persona was provided.")
                result = set_ui_persona(self.app_config, persona_id)
                return self.redirect(return_to + "?message=" + urllib.parse.quote(result))

            return self.respond_error(HTTPStatus.NOT_FOUND, "Route not found.")
        except (BrokenPipeError, ConnectionAbortedError, ConnectionResetError):
            return
        except Exception as exc:
            return self.redirect("/?message=" + urllib.parse.quote(f"Action failed: {exc}"))

    def respond_html(self, body: str, status: HTTPStatus = HTTPStatus.OK) -> None:
        encoded = body.encode("utf-8")
        try:
            self.send_response(status)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(encoded)))
            self.end_headers()
            self.wfile.write(encoded)
        except (BrokenPipeError, ConnectionAbortedError, ConnectionResetError):
            return

    def respond_json(self, payload: Any, status: HTTPStatus = HTTPStatus.OK) -> None:
        encoded = json.dumps(payload, indent=2).encode("utf-8")
        try:
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(encoded)))
            self.end_headers()
            self.wfile.write(encoded)
        except (BrokenPipeError, ConnectionAbortedError, ConnectionResetError):
            return

    def respond_error(self, status: HTTPStatus, message: str) -> None:
        self.respond_html(html_page(f"{status.value} {status.phrase}", f'<section class="panel"><h1>{status.value} {status.phrase}</h1><p>{esc(message)}</p><p><a href="/">Back to dashboard</a></p></section>'), status)

    def redirect(self, location: str) -> None:
        try:
            self.send_response(HTTPStatus.SEE_OTHER)
            self.send_header("Location", location)
            self.end_headers()
        except (BrokenPipeError, ConnectionAbortedError, ConnectionResetError):
            return

    def log_message(self, format: str, *args: Any) -> None:
        return


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Codex Monitor management UI.")
    parser.add_argument("--host", default="127.0.0.1", help="Bind address.")
    parser.add_argument("--port", type=int, default=8765, help="Bind port.")
    parser.add_argument("--settings", default=str(Path(__file__).resolve().parent / "codex-monitor.settings.json"), help="Path to codex-monitor.settings.json.")
    parser.add_argument("--open-browser", action="store_true", help="Open the dashboard in the default browser on startup.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    config = load_settings(Path(args.settings))
    server = ThreadingHTTPServer((args.host, args.port), CodexUiHandler)
    server.app_config = config  # type: ignore[attr-defined]
    url = f"http://{args.host}:{args.port}/"
    print(f"Codex Monitor UI listening on {url}")
    if args.open_browser:
        threading.Timer(0.6, lambda: webbrowser.open(url)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
