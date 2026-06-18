import argparse
import html
import json
import sqlite3
import subprocess
import sys
import threading
import urllib.parse
import webbrowser
from dataclasses import dataclass
from datetime import datetime, timezone
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


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def pretty_time(value: Any) -> str:
    if value in (None, ""):
        return "—"
    text = str(value).strip()
    if not text:
        return "—"
    candidates = [text]
    if text.endswith("Z"):
        candidates.append(text.replace("Z", "+00:00"))
    for candidate in candidates:
        try:
            dt = datetime.fromisoformat(candidate)
            if dt.tzinfo is not None:
                dt = dt.astimezone()
            return dt.strftime("%Y-%m-%d %H:%M:%S")
        except ValueError:
            continue
    return text


def parse_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as handle:
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
    :root {{
      --bg: #f2efe7;
      --panel: #fffaf0;
      --ink: #1f2430;
      --muted: #6b7280;
      --line: #d8d1c2;
      --accent: #8b1e3f;
      --accent-2: #1f5f8b;
      --ok: #1f7a3d;
      --warn: #b7791f;
      --high: #b42318;
      --shadow: 0 12px 30px rgba(31,36,48,.08);
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      background:
        radial-gradient(circle at top left, rgba(139,30,63,.08), transparent 30%),
        radial-gradient(circle at top right, rgba(31,95,139,.08), transparent 28%),
        linear-gradient(180deg, #f8f4ec 0%, var(--bg) 100%);
      color: var(--ink);
      font: 14px/1.5 "Segoe UI Variable Text", "Bahnschrift", "Trebuchet MS", sans-serif;
    }}
    a {{ color: var(--accent-2); text-decoration: none; }}
    a:hover {{ text-decoration: underline; }}
    .shell {{
      max-width: 1500px;
      margin: 0 auto;
      padding: 28px 24px 48px;
    }}
    .hero {{
      display: grid;
      gap: 16px;
      grid-template-columns: 2fr 1fr;
      margin-bottom: 24px;
    }}
    .panel {{
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 18px;
      box-shadow: var(--shadow);
      padding: 18px;
    }}
    .hero-main {{
      background: linear-gradient(135deg, #fffaf0 0%, #fdf2e9 100%);
    }}
    .kicker {{
      text-transform: uppercase;
      letter-spacing: .12em;
      color: var(--muted);
      font-size: 12px;
      margin-bottom: 6px;
    }}
    h1, h2, h3 {{ margin: 0 0 12px; font-weight: 650; }}
    h1 {{ font-size: 30px; }}
    h2 {{ font-size: 20px; }}
    h3 {{ font-size: 15px; color: var(--muted); }}
    .lede {{ margin: 0; color: var(--muted); max-width: 72ch; }}
    .grid {{
      display: grid;
      gap: 18px;
    }}
    .grid.two {{ grid-template-columns: repeat(2, minmax(0, 1fr)); }}
    .grid.three {{ grid-template-columns: repeat(3, minmax(0, 1fr)); }}
    .stack > * + * {{ margin-top: 14px; }}
    .cards {{
      display: grid;
      gap: 14px;
      grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
    }}
    .metric {{
      padding: 14px;
      border: 1px solid var(--line);
      border-radius: 14px;
      background: rgba(255,255,255,.62);
    }}
    .metric .label {{
      color: var(--muted);
      font-size: 12px;
      text-transform: uppercase;
      letter-spacing: .08em;
    }}
    .metric .value {{
      font-size: 22px;
      font-weight: 700;
      margin-top: 4px;
      overflow-wrap: anywhere;
    }}
    .status-pill {{
      display: inline-flex;
      align-items: center;
      gap: 8px;
      padding: 8px 12px;
      border-radius: 999px;
      font-weight: 650;
      background: #ece8de;
      color: var(--ink);
    }}
    .status-Healthy {{ background: rgba(31,122,61,.12); color: var(--ok); }}
    .status-Warning {{ background: rgba(183,121,31,.15); color: var(--warn); }}
    .status-High {{ background: rgba(180,35,24,.12); color: var(--high); }}
    .task {{
      border: 1px solid var(--line);
      border-radius: 14px;
      padding: 14px;
      background: rgba(255,255,255,.55);
    }}
    .task-head {{
      display: flex;
      align-items: flex-start;
      justify-content: space-between;
      gap: 12px;
      margin-bottom: 10px;
    }}
    .task-name {{ font-size: 17px; font-weight: 650; }}
    .task-meta {{ color: var(--muted); font-size: 13px; overflow-wrap: anywhere; }}
    .task-actions {{
      display: flex;
      gap: 10px;
      align-items: center;
      flex-wrap: wrap;
    }}
    .btn {{
      display: inline-flex;
      align-items: center;
      justify-content: center;
      padding: 8px 12px;
      border: 1px solid var(--line);
      border-radius: 10px;
      background: #fff;
      color: var(--ink);
      cursor: pointer;
      font: inherit;
    }}
    .btn.primary {{
      background: var(--accent);
      color: white;
      border-color: var(--accent);
    }}
    .btn:hover {{ filter: brightness(0.98); text-decoration: none; }}
    .kv {{
      display: grid;
      grid-template-columns: 180px 1fr;
      gap: 6px 12px;
      font-size: 13px;
    }}
    .kv dt {{ color: var(--muted); }}
    .kv dd {{ margin: 0; overflow-wrap: anywhere; }}
    pre {{
      margin: 0;
      padding: 14px;
      border-radius: 14px;
      border: 1px solid var(--line);
      background: #1f2430;
      color: #f7f8fa;
      overflow: auto;
      font: 12px/1.45 "Cascadia Code", "Consolas", monospace;
    }}
    table {{
      width: 100%;
      border-collapse: collapse;
      font-size: 13px;
    }}
    th, td {{
      padding: 10px 8px;
      border-bottom: 1px solid var(--line);
      vertical-align: top;
      text-align: left;
      overflow-wrap: anywhere;
    }}
    th {{ color: var(--muted); font-weight: 650; }}
    .finding {{
      padding: 10px 12px;
      border-radius: 12px;
      border: 1px solid var(--line);
      background: rgba(255,255,255,.5);
    }}
    .finding.high {{ border-color: rgba(180,35,24,.28); background: rgba(180,35,24,.06); }}
    .finding.medium {{ border-color: rgba(183,121,31,.28); background: rgba(183,121,31,.06); }}
    .path {{
      font: 12px/1.45 "Cascadia Code", "Consolas", monospace;
      color: var(--muted);
      overflow-wrap: anywhere;
    }}
    .flash {{
      margin-bottom: 18px;
      padding: 12px 14px;
      border-radius: 12px;
      border: 1px solid rgba(31,95,139,.24);
      background: rgba(31,95,139,.08);
    }}
    .mini {{ font-size: 12px; color: var(--muted); }}
    @media (max-width: 1100px) {{
      .hero, .grid.two, .grid.three {{ grid-template-columns: 1fr; }}
      .kv {{ grid-template-columns: 1fr; }}
    }}
  </style>
</head>
<body>
  <div class="shell">
    {body}
  </div>
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
    repo_root: Path


def load_settings(settings_path: Path) -> AppConfig:
    repo_root = Path(__file__).resolve().parent
    settings = {}
    if settings_path.exists():
        settings = parse_json(settings_path)

    runtime_root = Path(settings.get("RuntimeRoot") or settings_path.parent).resolve()
    data_root = Path(settings.get("DataRoot") or runtime_root).resolve()
    state_db_path = Path(settings.get("StateDbPath") or data_root / "state" / "ioc-store.db").resolve()
    alert_inbox_path = Path(settings.get("AlertInboxPath") or settings.get("AlertWatchPath") or data_root / "alerts" / "pending").resolve()
    alert_archive_path = Path(settings.get("AlertArchivePath") or data_root / "alerts" / "archive").resolve()
    indicator_export_path = Path(settings.get("IndicatorExportPath") or data_root / "indicators" / "feed-indicators-latest.json").resolve()

    return AppConfig(
        settings_path=settings_path.resolve(),
        runtime_root=runtime_root,
        data_root=data_root,
        state_db_path=state_db_path,
        alert_inbox_path=alert_inbox_path,
        alert_archive_path=alert_archive_path,
        indicator_export_path=indicator_export_path,
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
    LastTaskResult = if ($info) {{ [int]$info.LastTaskResult }} else {{ $null }}
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
    task_map = {
        "Codex Threat Feed Import": [
            "powershell",
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(config.runtime_root / "import-threat-feeds.ps1"),
        ],
        "Codex IOC Daily Scan": [
            "powershell",
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(config.runtime_root / "invoke-host-ioc.ps1"),
            "-Mode",
            "IOC",
        ],
        "Codex Host Tripwire": [
            "powershell",
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(config.runtime_root / "invoke-host-tripwire.ps1"),
            "-Mode",
            "Check",
            "-StateDbPath",
            str(config.state_db_path),
        ],
        "Codex Threat RSS Monitor": [
            "powershell",
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(config.runtime_root / "monitor-threat-rss.ps1"),
            "-StateDbPath",
            str(config.state_db_path),
            "-RunTripwireCheckOnMatch",
        ],
        "Codex Alert Notifier": [
            "powershell",
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(config.runtime_root / "start-codex-alert-helper.ps1"),
            "-WatchPath",
            str(config.alert_inbox_path),
            "-StateDbPath",
            str(config.state_db_path),
        ],
    }
    if task_name not in task_map:
        raise RuntimeError(f"Unknown task: {task_name}")
    result = run_process(task_map[task_name])
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or result.stdout.strip() or f"Failed to run task {task_name}")
    return result.stdout.strip() or f"Triggered monitor action: {task_name}"


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


def render_task(task: Dict[str, Any]) -> str:
    actions = task.get("Actions") or []
    triggers = task.get("Triggers") or []
    action_markup = "".join(
        f"<tr><td>{esc(action.get('Execute'))}</td><td>{esc(action.get('Arguments'))}</td><td>{esc(action.get('WorkingDirectory') or 'N/A')}</td></tr>"
        for action in actions
    ) or "<tr><td colspan='3' class='mini'>No actions found.</td></tr>"
    trigger_markup = "".join(
        f"<tr><td>{esc(trigger.get('Type'))}</td><td>{esc(trigger.get('StartBoundary') or 'N/A')}</td><td>{esc(trigger.get('RepetitionInterval') or 'N/A')}</td></tr>"
        for trigger in triggers
    ) or "<tr><td colspan='3' class='mini'>No triggers found.</td></tr>"
    return f"""
<div class="task">
  <div class="task-head">
    <div>
      <div class="task-name">{esc(task.get("Name"))}</div>
      <div class="task-meta">State={esc(task.get("State") or "Missing")} | Enabled={esc(task.get("Enabled"))} | LastResult={esc(task.get("LastTaskResult"))}</div>
    </div>
    <div class="task-actions">
      <form method="post" action="/run-task">
        <input type="hidden" name="task_name" value="{esc(task.get("Name"))}">
        <button class="btn primary" type="submit">Run now</button>
      </form>
    </div>
  </div>
  <dl class="kv">
    <dt>Author</dt><dd>{esc(task.get("Author") or "N/A")}</dd>
    <dt>Principal</dt><dd>{esc(task.get("Principal") or "N/A")} ({esc(task.get("RunLevel") or "N/A")})</dd>
    <dt>Last run</dt><dd>{esc(pretty_time(task.get("LastRunTime") or "N/A"))}</dd>
    <dt>Next run</dt><dd>{esc(pretty_time(task.get("NextRunTime") or "N/A"))}</dd>
    <dt>Description</dt><dd>{esc(task.get("Description") or "N/A")}</dd>
  </dl>
  <div class="stack">
    <div>
      <h3>Actions</h3>
      <table><thead><tr><th>Execute</th><th>Arguments</th><th>Working Dir</th></tr></thead><tbody>{action_markup}</tbody></table>
    </div>
    <div>
      <h3>Triggers</h3>
      <table><thead><tr><th>Type</th><th>Start</th><th>Repeat</th></tr></thead><tbody>{trigger_markup}</tbody></table>
    </div>
  </div>
</div>
"""


def render_alert_row(alert: Dict[str, Any]) -> str:
    encoded = urllib.parse.quote(alert["path"], safe="")
    return f"""
<tr>
  <td>{esc(alert.get("severity"))}</td>
  <td><a href="/alert?path={encoded}">{esc(alert.get("title"))}</a><div class="mini">{esc(alert.get("message"))}</div></td>
  <td>{esc(alert.get("change_count") if alert.get("change_count") is not None else "—")}</td>
  <td>{esc(pretty_time(alert.get("collection_time") or "—"))}</td>
</tr>
"""


def render_report_row(report: Dict[str, Any]) -> str:
    encoded = urllib.parse.quote(report["path"], safe="")
    summary_parts = [f"{key}={value}" for key, value in report.get("summary", {}).items() if value not in (None, "", 0)]
    summary_text = ", ".join(summary_parts) if summary_parts else "No summary fields"
    return f"""
<tr>
  <td><a href="/report?path={encoded}">{esc(report.get("name"))}</a></td>
  <td>{esc(report.get("report_type"))}</td>
  <td>{esc(pretty_time(report.get("collection_time") or "—"))}</td>
  <td>{esc(summary_text)}</td>
</tr>
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


def render_dashboard(config: AppConfig, snapshot: Dict[str, Any], message: str = "") -> str:
    status = snapshot["status"]
    indicators = snapshot["indicators"]
    pending_alerts = snapshot["pending_alerts"]
    archive_alerts = snapshot["archive_alerts"]
    recent_reports = snapshot["recent_reports"]
    findings = status.get("HealthFindings") or []
    finding_markup = "".join(
        f'<div class="finding {esc((finding.get("Severity") or "").lower())}"><strong>[{esc(finding.get("Severity"))}]</strong> {esc(finding.get("Message"))}</div>'
        for finding in findings
    ) or '<div class="finding">No health findings.</div>'
    task_markup = "".join(render_task(task) for task in snapshot["task_details"])
    pending_rows = "".join(render_alert_row(item) for item in pending_alerts[:20]) or "<tr><td colspan='4' class='mini'>No pending alerts.</td></tr>"
    archive_rows = "".join(render_alert_row(item) for item in archive_alerts[:20]) or "<tr><td colspan='4' class='mini'>No archived alerts.</td></tr>"
    report_rows = "".join(render_report_row(item) for item in recent_reports) or "<tr><td colspan='4' class='mini'>No reports found.</td></tr>"
    type_rows = "".join(f"<tr><td>{esc(row['type'])}</td><td>{esc(row['count'])}</td></tr>" for row in indicators["by_type"]) or "<tr><td colspan='2' class='mini'>No indicator data.</td></tr>"
    source_rows = "".join(f"<tr><td>{esc(row['source'])}</td><td>{esc(row['count'])}</td></tr>" for row in indicators["by_source"]) or "<tr><td colspan='2' class='mini'>No source data.</td></tr>"
    ingest_rows = "".join(
        f"<tr><td>{esc(run['source_name'])}</td><td>{esc(run['status'])}</td><td>{esc(run['indicator_count'])}</td><td>{esc(pretty_time(run['started_at']))}</td></tr>"
        for run in indicators["ingest_runs"]
    ) or "<tr><td colspan='4' class='mini'>No ingest runs found.</td></tr>"
    app_state_rows = "".join(
        f"<tr><td>{esc(row['namespace'])}</td><td>{esc(row['state_key'])}</td><td>{esc(row['updated_at'])}</td></tr>"
        for row in indicators["app_state"]
    ) or "<tr><td colspan='3' class='mini'>No app state found.</td></tr>"
    flash = f'<div class="flash">{esc(message)}</div>' if message else ""

    body = f"""
{flash}
<section class="hero">
  <div class="panel hero-main">
    <div class="kicker">Codex Monitor Control Surface</div>
    <h1>Threat Operations Dashboard</h1>
    <p class="lede">This dashboard surfaces the exact state and artifacts the scheduled tasks consume: SQLite app state, normalized indicator store, pending and archived alerts, task actions, schedules, and the latest IOC, tripwire, and RSS reports.</p>
  </div>
  <div class="panel">
    <div class="kicker">Current posture</div>
    <div class="status-pill status-{esc(status['Metadata']['OverallStatus'])}">{esc(status['Metadata']['OverallStatus'])}</div>
    <div class="stack" style="margin-top:12px">
      <div class="path">{esc(config.settings_path)}</div>
      <div class="path">{esc(config.state_db_path)}</div>
      <div class="path">{esc(config.alert_inbox_path)}</div>
    </div>
  </div>
</section>

<section class="panel">
  <div class="cards">
    {render_metric("Pending alerts", status["State"]["PendingAlertCount"])}
    {render_metric("Seen alerts", status["State"]["SeenAlertCount"])}
    {render_metric("Archived alerts", status["State"]["ArchivedAlertCount"])}
    {render_metric("Indicators", indicators["indicator_count"])}
    {render_metric("Tripwire baseline", pretty_time(status["State"]["TripwireBaselineCollectionTimeUtc"]) if status["State"]["TripwireBaselineCollectionTimeUtc"] else "Missing")}
    {render_metric("RSS last run", pretty_time(status["State"]["ThreatRssLastRunUtc"]) if status["State"]["ThreatRssLastRunUtc"] else "Missing")}
  </div>
</section>

<section class="grid two" style="margin-top:18px">
  <div class="panel stack">
    <h2>Health Findings</h2>
    {finding_markup}
  </div>
  <div class="panel stack">
    <h2>Paths</h2>
    <div class="kv">
      <dt>Runtime root</dt><dd>{esc(config.runtime_root)}</dd>
      <dt>Data root</dt><dd>{esc(config.data_root)}</dd>
      <dt>State DB</dt><dd>{esc(config.state_db_path)}</dd>
      <dt>Indicator export</dt><dd>{esc(config.indicator_export_path)}</dd>
      <dt>Pending alerts</dt><dd>{esc(config.alert_inbox_path)}</dd>
      <dt>Archive alerts</dt><dd>{esc(config.alert_archive_path)}</dd>
    </div>
  </div>
</section>

<section class="panel stack" style="margin-top:18px">
  <h2>Scheduled Tasks</h2>
  {task_markup}
</section>

<section class="grid two" style="margin-top:18px">
  <div class="panel stack">
    <h2>Pending Alerts</h2>
    <table><thead><tr><th>Severity</th><th>Alert</th><th>Count</th><th>Collected</th></tr></thead><tbody>{pending_rows}</tbody></table>
  </div>
  <div class="panel stack">
    <h2>Archived Alerts</h2>
    <table><thead><tr><th>Severity</th><th>Alert</th><th>Count</th><th>Collected</th></tr></thead><tbody>{archive_rows}</tbody></table>
  </div>
</section>

<section class="grid three" style="margin-top:18px">
  <div class="panel stack">
    <h2>Indicator Types</h2>
    <table><thead><tr><th>Type</th><th>Count</th></tr></thead><tbody>{type_rows}</tbody></table>
  </div>
  <div class="panel stack">
    <h2>Indicator Sources</h2>
    <table><thead><tr><th>Source</th><th>Count</th></tr></thead><tbody>{source_rows}</tbody></table>
  </div>
  <div class="panel stack">
    <h2>SQLite App State</h2>
    <table><thead><tr><th>Namespace</th><th>Key</th><th>Updated</th></tr></thead><tbody>{app_state_rows}</tbody></table>
  </div>
</section>

<section class="grid two" style="margin-top:18px">
  <div class="panel stack">
    <h2>Ingest Runs</h2>
    <table><thead><tr><th>Source</th><th>Status</th><th>Indicators</th><th>Started</th></tr></thead><tbody>{ingest_rows}</tbody></table>
  </div>
  <div class="panel stack">
    <h2>Recent Reports</h2>
    <table><thead><tr><th>Report</th><th>Type</th><th>Collected</th><th>Summary</th></tr></thead><tbody>{report_rows}</tbody></table>
  </div>
</section>
"""
    return html_page("Codex Monitor UI", body)


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

            if parsed.path == "/run-task":
                task_name = payload.get("task_name", [""])[0]
                if task_name not in TASK_NAMES:
                    raise RuntimeError("Unknown task requested.")
                result = run_task(task_name, self.app_config)
                return self.redirect("/?message=" + urllib.parse.quote(result))

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
