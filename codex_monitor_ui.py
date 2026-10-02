import argparse
import copy
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

import codex_monitor_store as ioc_store
import csf_catalog


TASK_NAMES = [
    "Codex Threat Feed Import",
    "Codex IOC Daily Scan",
    "Codex Host Tripwire",
    "Codex Threat RSS Monitor",
    "Codex Alert Notifier",
]

TRIPWIRE_BASELINE_TASK_NAME = "Codex Host Tripwire Baseline (System)"
CSF_ANALYST_PERSONA_ID = "analyst"
UI_DISPLAY_VERSION = "1.0"
PRODUCT_DISPLAY_NAME = "CSF Analyst UI"
FRAMEWORK_DISPLAY_NAME = "National Institute of Standards and Technology Cybersecurity Framework (NIST CSF) 2"

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


UI_CLIENT_SCRIPT = """
<script>
(() => {
  const fragmentUrl = (href, fragment) => {
    const url = new URL(href, window.location.origin);
    url.searchParams.set("fragment", fragment);
    return url.toString();
  };

  const replaceWorkspace = (markup, focusExplorerList = "") => {
    const current = document.getElementById("csf-app");
    if (!current) return false;
    current.outerHTML = markup;
    requestAnimationFrame(() => {
      document.querySelectorAll(".csf-explorer-list .csf-explorer-row.active").forEach((row) => {
        row.scrollIntoView({ block: "nearest", inline: "nearest" });
      });
      if (focusExplorerList) document.querySelector(`.csf-explorer-list[data-explorer-list="${focusExplorerList}"]`)?.focus({ preventScroll: true });
    });
    return true;
  };

  const navigate = async (href, push, focusExplorerList = "") => {
    const app = document.getElementById("csf-app");
    if (!app) { window.location.assign(href); return; }
    app.setAttribute("aria-busy", "true");
    try {
      const response = await fetch(fragmentUrl(href, "app"), { headers: { "X-Codex-Fragment": "app" } });
      if (!response.ok || !replaceWorkspace(await response.text(), focusExplorerList)) throw new Error("Workspace response was unavailable.");
      if (push) window.history.pushState({ csfWorkspace: true }, "", href);
    } catch (_) {
      window.location.assign(href);
    }
  };

  const listScrollStep = (list) => {
    const row = list.querySelector(".csf-explorer-row, .csf-record-row, .csf-profile-choice");
    if (!row) return 0;
    const rowGap = Number.parseFloat(window.getComputedStyle(list).rowGap) || 0;
    return row.getBoundingClientRect().height + rowGap;
  };

  const scrollListByRow = (list, direction) => {
    const step = listScrollStep(list);
    if (!step || list.scrollHeight <= list.clientHeight) return false;
    const currentRow = Math.round(list.scrollTop / step);
    const maxRow = Math.round((list.scrollHeight - list.clientHeight) / step);
    const nextRow = Math.max(0, Math.min(maxRow, currentRow + direction));
    if (nextRow === currentRow) return false;
    list.scrollTo({ top: nextRow * step, behavior: "auto" });
    return true;
  };

  const closeModal = () => {
    const host = document.getElementById("csf-modal-host");
    const dialog = host?.querySelector("[role=dialog]");
    const returnFocus = dialog?.dataset.returnFocus;
    if (host) host.replaceChildren();
    if (returnFocus) document.getElementById(returnFocus)?.focus();
  };

  const openModal = async (href, opener) => {
    const host = document.getElementById("csf-modal-host");
    if (!host) { window.location.assign(href); return; }
    try {
      const response = await fetch(fragmentUrl(href, "modal"), { headers: { "X-Codex-Fragment": "modal" } });
      if (!response.ok) throw new Error("Detail response was unavailable.");
      host.innerHTML = await response.text();
      const dialog = host.querySelector("[role=dialog]");
      if (dialog) {
        dialog.dataset.returnFocus = opener ? opener.id : "";
        dialog.querySelector("[data-modal-close]")?.focus();
      }
    } catch (_) {
      window.location.assign(href);
    }
  };

  const guidanceFunctionClasses = [
    "csf-function-govern", "csf-function-identify", "csf-function-protect",
    "csf-function-detect", "csf-function-respond", "csf-function-recover",
  ];

  const functionClassFor = (element) => guidanceFunctionClasses.find((name) => element?.classList?.contains(name));

  const setGuidance = (source) => {
    const app = document.getElementById("csf-app");
    const purpose = document.getElementById("csf-guidance-purpose");
    const useHere = document.getElementById("csf-guidance-use");
    if (!app || !purpose || !useHere) return;
    purpose.textContent = source?.dataset.csfPurpose || app.dataset.csfGuidancePurpose || "";
    useHere.textContent = source?.dataset.csfUse || app.dataset.csfGuidanceUse || "";
    const guidance = document.querySelector(".csf-guidance");
    const functionClass = functionClassFor(source) || functionClassFor(document.querySelector(".csf-action.active"));
    if (guidance && functionClass) {
      guidance.classList.remove(...guidanceFunctionClasses);
      guidance.classList.add(functionClass);
    }
  };

  document.addEventListener("click", (event) => {
    const modalClose = event.target.closest("button[data-modal-close]");
    const backdrop = event.target.closest(".modal-backdrop");
    if (modalClose || (backdrop && event.target === backdrop)) { event.preventDefault(); closeModal(); return; }
    const informationFlow = event.target.closest("button[data-information-flow-modal]");
    if (informationFlow) {
      event.preventDefault();
      const host = document.getElementById("csf-modal-host");
      const template = document.getElementById("csf-information-flow-template");
      if (!host || !template) return;
      if (!informationFlow.id) informationFlow.id = `information-flow-opener-${Date.now()}`;
      host.replaceChildren(template.content.cloneNode(true));
      const direction = informationFlow.dataset.informationFlowDirection || "all";
      if (direction !== "all") {
        host.querySelectorAll("[data-information-flow-section]").forEach((section) => {
          section.hidden = section.dataset.informationFlowSection !== direction;
        });
      }
      const dialog = host.querySelector("[role=dialog]");
      if (dialog) {
        dialog.dataset.returnFocus = informationFlow.id;
        dialog.querySelector("[data-modal-close]")?.focus();
      }
      return;
    }
    const modalLink = event.target.closest("a[data-record-modal]");
    if (modalLink && event.button === 0 && !event.metaKey && !event.ctrlKey) {
      event.preventDefault();
      if (!modalLink.id) modalLink.id = `modal-opener-${Date.now()}`;
      openModal(modalLink.href, modalLink);
      return;
    }
    const route = event.target.closest("a[data-csf-route]");
    if (route && event.button === 0 && !event.metaKey && !event.ctrlKey) {
      event.preventDefault();
      navigate(route.href, true, route.closest(".csf-explorer-list")?.dataset.explorerList || "");
    }
  });

  document.addEventListener("submit", (event) => {
    if (event.submitter?.matches("[data-confirm-delete]") && !window.confirm("Delete this action and all of its progress updates? This cannot be undone.")) {
      event.preventDefault();
      return;
    }
    if (event.submitter?.matches("[data-confirm-profile-delete]") && !window.confirm("Delete this profile from the workspace? It will be removed from selection, while its append-only audit history is retained.")) {
      event.preventDefault();
    }
  });

  document.addEventListener("change", (event) => {
    const profileEditorForm = event.target?.closest("#profile-edit-form");
    if (profileEditorForm) {
      const saveAll = profileEditorForm.querySelector("button[data-profile-save-all]");
      if (saveAll) {
        saveAll.disabled = false;
        saveAll.classList.remove("is-saved");
        saveAll.classList.add("is-dirty");
        saveAll.textContent = "Save profile changes";
      }
    }
    const profileControl = event.target;
    const profileForm = profileControl?.form;
    if (profileForm?.action?.includes("/set-csf-profile-outcome-target")) {
      const saveButton = [...document.querySelectorAll("button[data-profile-outcome-save]")].find((button) => button.form === profileForm);
      if (saveButton) {
        saveButton.classList.remove("is-saved");
        saveButton.classList.add("is-dirty");
        saveButton.textContent = "Save changes";
      }
    }
    const control = event.target.closest("input[data-action-title-example]");
    if (!control?.checked) return;
    const form = control.closest("form");
    for (const [selector, example] of [
      ['input[name="title"]', control.dataset.actionTitleExample],
      ['textarea[name="details"]', control.dataset.actionDetailsExample],
      ['textarea[name="rationale"]', control.dataset.actionRationaleExample],
    ]) {
      const field = form?.querySelector(selector);
      if (field && !field.value && example) field.placeholder = `Example: ${example}`;
    }
  });

  document.addEventListener("input", (event) => {
    const profileEditorForm = event.target?.closest("#profile-edit-form");
    if (profileEditorForm) {
      const saveAll = profileEditorForm.querySelector("button[data-profile-save-all]");
      if (saveAll) {
        saveAll.disabled = false;
        saveAll.classList.remove("is-saved");
        saveAll.classList.add("is-dirty");
        saveAll.textContent = "Save profile changes";
      }
    }
    const profileForm = event.target?.form;
    if (!profileForm?.action?.includes("/set-csf-profile-outcome-target")) return;
    const saveButton = [...document.querySelectorAll("button[data-profile-outcome-save]")].find((button) => button.form === profileForm);
    if (!saveButton) return;
    saveButton.classList.remove("is-saved");
    saveButton.classList.add("is-dirty");
    saveButton.textContent = "Save changes";
  });

  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape" && document.querySelector("#csf-modal-host [role=dialog]")) closeModal();
    const explorerList = event.target.closest?.(".csf-explorer-list, .csf-record-list");
    if (explorerList && (event.key === "ArrowDown" || event.key === "ArrowUp")) {
      event.preventDefault();
      scrollListByRow(explorerList, event.key === "ArrowDown" ? 1 : -1);
    }
  });

  document.addEventListener("wheel", (event) => {
    const explorerList = event.target.closest?.(".csf-explorer-list, .csf-record-list");
    if (!explorerList || !event.deltaY) return;
    event.preventDefault();
    scrollListByRow(explorerList, event.deltaY > 0 ? 1 : -1);
  }, { passive: false });

  document.addEventListener("mouseover", (event) => {
    const route = event.target.closest("a[data-csf-route]");
    if (route && !route.contains(event.relatedTarget)) setGuidance(route);
  });

  document.addEventListener("mouseout", (event) => {
    const route = event.target.closest("a[data-csf-route]");
    if (route && !route.contains(event.relatedTarget)) setGuidance();
  });

  document.addEventListener("focusin", (event) => {
    const route = event.target.closest("a[data-csf-route]");
    if (route) setGuidance(route);
  });

  document.addEventListener("focusout", (event) => {
    const route = event.target.closest("a[data-csf-route]");
    if (route && !route.contains(event.relatedTarget)) setGuidance();
  });

  window.addEventListener("popstate", () => navigate(window.location.href, false));
})();
</script>
"""


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
    .hero {{ display:grid; gap:18px; grid-template-columns:minmax(0,2fr) minmax(320px,.95fr); align-items:stretch; }} .hero.single {{ grid-template-columns:1fr; }} .hero-main {{ position:relative; overflow:hidden; border-radius:30px; padding:34px; min-height:280px; --mood-glow: rgba(125,163,143,.22); --mood-wash: rgba(255,248,240,.92); --mood-image:none; background:linear-gradient(180deg,rgba(255,255,255,.75),var(--mood-wash)),radial-gradient(circle at 75% 22%, var(--mood-glow), transparent 24%),radial-gradient(circle at 15% 82%, rgba(135,169,194,.18), transparent 26%),linear-gradient(135deg,#fcfbf8 0%,#f2ece2 100%); border:1px solid rgba(34,50,59,.10); box-shadow:0 26px 60px rgba(93,102,108,.12); }}
    .hero-main.mood-steady {{ --mood-glow: rgba(125,163,143,.24); --mood-wash: rgba(244,250,245,.92); }}
    .hero-main.mood-needs_review {{ --mood-glow: rgba(216,171,99,.24); --mood-wash: rgba(255,249,239,.94); }}
    .hero-main.mood-action_needed {{ --mood-glow: rgba(187,123,114,.24); --mood-wash: rgba(253,244,242,.94); }}
    .hero-main::before {{ content:""; position:absolute; inset:0; pointer-events:none; background-image:var(--mood-image); background-size:cover; background-position:center; opacity:.08; }}
    .page-topbar {{ display:flex; align-items:center; justify-content:space-between; gap:16px; margin-bottom:14px; }} .brand-mark {{ display:inline-flex; align-items:center; gap:10px; font-size:13px; color:var(--muted); text-transform:uppercase; letter-spacing:.16em; font-weight:700; }} .brand-dot {{ width:12px; height:12px; border-radius:999px; background:linear-gradient(135deg,#9ec0ab,#83a9c8); box-shadow:0 0 0 6px rgba(125,163,143,.10); }}
    .kicker {{ text-transform:uppercase; letter-spacing:.14em; color:#698576; font-size:11px; margin-bottom:12px; font-weight:700; }} h1,h2,h3 {{ margin:0; letter-spacing:-.03em; color:var(--ink); }} h1 {{ font-size:46px; line-height:1.02; max-width:12ch; margin-bottom:14px; font-weight:650; }} h2 {{ font-size:24px; margin-bottom:14px; font-weight:620; }} h3 {{ font-size:12px; text-transform:uppercase; letter-spacing:.12em; color:var(--muted); margin-bottom:12px; font-weight:700; }} .lede {{ margin:0; max-width:64ch; font-size:16px; color:#5f6e76; }}
    .hero-actions,.task-actions,.subnav {{ display:flex; gap:10px; align-items:center; flex-wrap:wrap; }} .hero-actions {{ margin-top:24px; }} .hero-meta {{ display:flex; gap:10px; flex-wrap:wrap; margin-top:18px; color:var(--muted); font-size:13px; }} .csf-map {{ max-width:1260px; margin:0 auto; text-align:center; }} .app-masthead {{ display:flex; align-items:baseline; justify-content:space-between; gap:16px; margin-bottom:14px; text-align:left; }} .app-title-context {{ display:flex; align-items:center; gap:14px; min-width:0; flex-wrap:wrap; }} .app-title {{ color:var(--ink); font-size:19px; font-weight:700; letter-spacing:-.02em; }} .csf-profile-selector {{ margin-left:48px; }} .csf-profile-selector label {{ display:flex; align-items:center; gap:7px; color:var(--muted); font-size:12px; font-weight:700; white-space:nowrap; }} .csf-profile-selector select {{ max-width:240px; padding:5px 24px 5px 8px; border:1px solid rgba(34,50,59,.16); border-radius:8px; background:#fff; color:var(--ink); font:inherit; font-weight:600; }} .app-header-actions {{ display:flex; align-items:center; }} .app-home-link {{ display:inline-flex; align-items:center; justify-content:center; padding:8px 13px; border:1px solid rgba(34,50,59,.12); border-radius:999px; background:rgba(255,255,255,.82); color:var(--ink); font-size:12px; font-weight:700; text-decoration:none; white-space:nowrap; }} .app-home-link:hover {{ color:#315345; background:var(--sage-soft); }} .csf-map .kicker {{ margin-bottom:16px; }} .csf-action-bar {{ display:grid; gap:28px; grid-template-columns:repeat(6,minmax(0,1fr)); }} .csf-action {{ position:relative; display:grid; align-content:center; gap:7px; min-height:118px; padding:18px 14px; border:1px solid var(--line); border-radius:14px; background:rgba(255,255,255,.68); color:var(--ink); text-align:center; }} .csf-action:not(:last-child)::after {{ content:"→"; position:absolute; z-index:2; top:50%; right:-23px; transform:translateY(-50%); width:18px; color:#698576; font-size:18px; font-weight:700; line-height:1; pointer-events:none; }} .csf-action span {{ font-size:12px; font-weight:750; text-transform:uppercase; letter-spacing:.08em; }} .csf-action small {{ color:var(--muted); font-size:11px; line-height:1.35; }} .csf-action.csf-function-govern {{ --csf-function-color:#f9f49d; --csf-function-ink:#3b3b1f; }} .csf-action.csf-function-identify {{ --csf-function-color:#4bb2e0; --csf-function-ink:#163b4d; }} .csf-action.csf-function-protect {{ --csf-function-color:#9292ea; --csf-function-ink:#292957; }} .csf-action.csf-function-detect {{ --csf-function-color:#fab746; --csf-function-ink:#563914; }} .csf-action.csf-function-respond {{ --csf-function-color:#f97367; --csf-function-ink:#5a2722; }} .csf-action.csf-function-recover {{ --csf-function-color:#7df49f; --csf-function-ink:#1d4c2b; }} .csf-action[class*="csf-function-"] {{ background:color-mix(in srgb,var(--csf-function-color) 24%,white); border-color:color-mix(in srgb,var(--csf-function-color) 70%,#a7a9a7); color:var(--csf-function-ink); }} .csf-action[class*="csf-function-"]:hover {{ background:color-mix(in srgb,var(--csf-function-color) 42%,white); border-color:var(--csf-function-color); color:var(--csf-function-ink); }} .csf-action[class*="csf-function-"].active {{ background:var(--csf-function-color); border-color:var(--csf-function-color); box-shadow:0 12px 24px color-mix(in srgb,var(--csf-function-color) 36%,transparent); color:var(--csf-function-ink); }} .csf-guidance {{ display:grid; gap:6px; margin-top:14px; padding:14px; border-radius:16px; background:var(--blue-soft); border:1px solid rgba(135,169,194,.28); color:#415b6a; text-align:left; }} .csf-guidance strong {{ color:#2f4957; }} .csf-utilities {{ justify-content:center; margin-top:14px; }}
    .grid {{ display:grid; gap:18px; }} .grid.two {{ grid-template-columns:repeat(2,minmax(0,1fr)); }} .grid.three {{ grid-template-columns:repeat(3,minmax(0,1fr)); }} .dashboard-start-tiles {{ display:grid; grid-template-columns:repeat(2,minmax(0,1fr)); grid-auto-rows:1fr; gap:18px; }} .dashboard-start-tiles > .panel {{ height:100%; box-sizing:border-box; }} .stack > * + * {{ margin-top:14px; }} .cards {{ display:grid; gap:14px; grid-template-columns:repeat(auto-fit,minmax(180px,1fr)); }}
    .metric,.focus-card,.care-tile,.task,.activity-item,.mood-chip {{ background:rgba(255,255,255,.76); border:1px solid rgba(34,50,59,.10); border-radius:18px; }} .metric {{ padding:16px; min-height:104px; }} .metric .label,.mood-chip .label {{ color:var(--muted); font-size:11px; text-transform:uppercase; letter-spacing:.12em; font-weight:700; }} .metric .value {{ font-size:26px; font-weight:650; margin-top:7px; color:var(--ink); overflow-wrap:anywhere; }} .metric .value .metric-time-sub {{ display:block; font-size:15px; line-height:1.25; margin-top:5px; color:#607079; font-weight:500; }}
    .status-pill {{ display:inline-flex; align-items:center; gap:8px; white-space:nowrap; padding:8px 13px; border-radius:999px; font-size:12px; font-weight:700; border:1px solid transparent; }} .status-ok,.status-Healthy {{ background:var(--sage-soft); color:#4d705d; border-color:rgba(125,163,143,.35); }} .status-medium,.status-Warning {{ background:var(--amber-soft); color:#8a6735; border-color:rgba(216,171,99,.32); }} .status-high,.status-High {{ background:var(--rose-soft); color:#90564c; border-color:rgba(187,123,114,.28); }} .status-info {{ background:var(--blue-soft); color:#58758a; border-color:rgba(135,169,194,.32); }}
    .btn {{ display:inline-flex; align-items:center; justify-content:center; gap:8px; padding:10px 16px; border-radius:999px; border:1px solid rgba(34,50,59,.12); background:rgba(255,255,255,.82); color:var(--ink); font:inherit; cursor:pointer; transition:transform .14s ease, box-shadow .14s ease; }} .btn:hover {{ transform:translateY(-1px); box-shadow:0 12px 24px rgba(80,88,94,.10); }} .btn:disabled {{ cursor:not-allowed; opacity:.52; }} .btn:disabled:hover {{ transform:none; box-shadow:none; }} .btn.primary {{ background:linear-gradient(135deg,#8eb39d,#86a9c2); color:#fff; border-color:transparent; font-weight:700; }} .btn.danger {{ color:#904f48; border-color:rgba(187,123,114,.35); background:rgba(246,231,227,.62); }} .btn.active {{ background:#eef3ee; border-color:rgba(125,163,143,.28); }} .csf-profile-save.is-dirty {{ background:var(--amber-soft); border-color:rgba(216,171,99,.60); color:#765526; font-weight:700; }} .csf-profile-save.is-saved {{ background:var(--sage-soft); border-color:rgba(125,163,143,.60); color:#315345; font-weight:700; }}
    .csf-outcome-history-cell {{ padding:0 12px 12px; background:rgba(232,240,234,.34); }} .csf-outcome-history {{ width:100%; box-sizing:border-box; max-height:96px; overflow-y:auto; border:1px solid rgba(34,50,59,.10); border-radius:10px; background:rgba(255,255,255,.75); }} .csf-outcome-history-item {{ display:grid; grid-template-columns:205px minmax(340px,1.25fr) minmax(300px,2fr) minmax(180px,1fr); gap:14px; width:100%; box-sizing:border-box; padding:7px 10px; border-bottom:1px solid rgba(34,50,59,.07); font-size:12px; }} .csf-outcome-history-item strong {{ white-space:nowrap; }} .csf-outcome-history-item:last-child {{ border-bottom:0; }}
    .profile-audit-log {{ table-layout:fixed; }} .profile-audit-log .audit-recorded-at {{ width:190px; white-space:nowrap; }} .profile-audit-log .audit-recorded-by {{ width:110px; }} .profile-audit-log .audit-outcome {{ width:85px; }} .profile-audit-log .audit-change {{ width:360px; white-space:nowrap; }} .profile-audit-log .audit-reason {{ width:23%; }} .profile-audit-log .audit-evidence {{ width:auto; }}
    .profile-tailoring-head {{ display:flex; align-items:end; justify-content:space-between; gap:16px; margin-top:8px; }} .profile-tailoring-head h3 {{ margin:0; }}
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
    .csf-workspace {{ display:grid; gap:18px; }} .workspace-scroll {{ min-width:0; }} .workspace-scroll > * + * {{ margin-top:18px; }} .workspace-scroll .grid.two,.workspace-scroll .grid.three {{ grid-template-columns:minmax(0,1fr); }} .csf-explorer {{ display:grid; gap:10px; }} .csf-explorer-head {{ display:flex; align-items:flex-start; justify-content:space-between; gap:18px; }} .csf-explorer-list-panel {{ display:grid; grid-template-rows:auto minmax(0,1fr); gap:6px; min-height:0; }} .csf-explorer-list-panel h3 {{ margin:0; }} .csf-explorer-list {{ display:grid; grid-auto-rows:104px; gap:8px; height:104px; max-height:104px; overflow:auto; padding-right:4px; overscroll-behavior:contain; }} .csf-explorer-list:focus {{ outline:2px solid rgba(135,169,194,.72); outline-offset:3px; border-radius:14px; }} .csf-explorer-row {{ display:grid; grid-template-columns:106px minmax(180px,.6fr) minmax(0,1.8fr); align-items:center; gap:12px; height:104px; overflow:hidden; padding:11px 13px; border:1px solid rgba(34,50,59,.10); border-radius:14px; background:rgba(255,255,255,.72); color:var(--ink); text-align:left; }} .csf-explorer-row:hover {{ background:var(--blue-soft); border-color:rgba(135,169,194,.42); }} .csf-explorer-row.active {{ background:var(--sage-soft); border-color:rgba(125,163,143,.48); box-shadow:inset 4px 0 0 #7da38f; }} .csf-explorer-id {{ font-size:12px; font-weight:750; letter-spacing:.05em; color:#4f6c7e; }} .csf-explorer-title {{ font-weight:700; }} .csf-explorer-copy {{ display:-webkit-box; overflow:hidden; -webkit-box-orient:vertical; -webkit-line-clamp:3; color:var(--muted); font-size:13px; }} .csf-explorer-placeholder {{ padding:18px; border:1px dashed rgba(34,50,59,.20); border-radius:16px; color:var(--muted); background:rgba(248,245,239,.70); }} .csf-outcome {{ display:grid; gap:12px; padding:18px; border-radius:18px; background:rgba(232,239,245,.55); border:1px solid rgba(135,169,194,.28); }} .csf-outcome .focus-title {{ font-size:20px; }} .csf-outcome h3 {{ margin:0; }} .csf-outcome p {{ margin:0; color:#475861; }} .csf-outcome-state {{ padding:12px 14px; border-radius:14px; background:rgba(255,255,255,.76); border:1px solid rgba(34,50,59,.10); }} .modal-backdrop {{ position:fixed; inset:0; z-index:50; display:grid; place-items:center; padding:16px; background:rgba(26,39,47,.42); }} .modal-dialog {{ width:min(860px,100%); max-height:calc(100vh - 32px); display:grid; grid-template-rows:auto minmax(0,1fr); overflow:hidden; border:1px solid rgba(34,50,59,.18); border-radius:24px; background:var(--panel); box-shadow:0 28px 80px rgba(20,32,38,.32); }} .modal-head {{ display:flex; align-items:center; justify-content:space-between; gap:16px; padding:18px 22px; border-bottom:1px solid var(--line); }} .modal-body {{ min-height:0; overflow:auto; padding:20px 22px; }} .modal-body .panel {{ box-shadow:none; }}
    @media (min-width:1000px) and (min-height:1000px) {{ html,body {{ height:100%; overflow:hidden; }} .shell {{ height:100vh; max-width:none; padding:14px 18px; }} .page-stack,#csf-app {{ height:100%; min-height:0; }} .page-stack > * + * {{ margin-top:0; }} #csf-app {{ display:grid; grid-template-rows:auto minmax(0,1fr); gap:12px; }} .csf-map {{ width:100%; max-width:none; padding:14px 18px; }} .app-masthead {{ margin-bottom:8px; }} .app-title {{ font-size:17px; }} .csf-map .kicker {{ display:none; }} .csf-action-bar {{ gap:32px; grid-template-columns:repeat(6,minmax(0,1fr)) !important; }} .csf-action {{ min-height:72px; padding:10px 12px; }} .csf-action:not(:last-child)::after {{ right:-25px; font-size:15px; }} .csf-guidance {{ grid-template-columns:auto 1fr; align-items:center; gap:10px; margin-top:10px; padding:9px 12px; }} .csf-utilities {{ display:none; }} .csf-workspace {{ min-height:0; grid-template-rows:minmax(0,1fr); gap:12px; overflow:hidden; }} .workspace-scroll {{ min-height:0; display:grid; grid-template-columns:minmax(0,1fr); grid-auto-rows:minmax(0,1fr); gap:12px; overflow:hidden; }} .workspace-scroll > .grid {{ display:contents; }} .workspace-scroll > .panel,.workspace-scroll > .grid > .panel {{ min-height:0; max-height:none; margin:0 !important; overflow:auto; overscroll-behavior:contain; }} .workspace-scroll > .csf-explorer {{ grid-column:1; }} .workspace-scroll > .csf-selection-list {{ grid-template-rows:auto minmax(0,1fr); overflow:hidden; }} .workspace-scroll > .csf-selection-list .csf-explorer-list-panel {{ min-height:0; }} .workspace-scroll > .csf-selection-list .csf-explorer-list {{ min-height:0; height:104px; max-height:104px; overflow:auto; }} .workspace-scroll > .panel:only-child {{ grid-column:1; }} .workspace-scroll .panel {{ padding:14px 18px; }} .workspace-scroll .grid {{ gap:12px; }} .workspace-scroll .task + .task {{ margin-top:10px; }} .workspace-scroll .metric {{ min-height:78px; padding:12px; }} .workspace-scroll .care-tile,.workspace-scroll .focus-card {{ padding:13px; }} }}
    @media (max-width:1100px) {{ .hero,.grid.two,.grid.three {{ grid-template-columns:1fr; }} .csf-action-bar {{ grid-template-columns:repeat(3,minmax(0,1fr)); }} .csf-action:not(:last-child)::after {{ display:none; }} h1 {{ max-width:none; font-size:38px; }} }} @media (max-width:760px) {{ .shell {{ padding:18px 14px 40px; }} .panel,.hero-main {{ padding:20px; }} .csf-action-bar,.dashboard-start-tiles {{ grid-template-columns:1fr; }} .csf-action {{ min-height:104px; }} .task-head,.page-topbar,.csf-explorer-head {{ flex-direction:column; align-items:flex-start; }} .csf-explorer-list {{ grid-auto-rows:auto; }} .csf-explorer-row {{ grid-template-columns:1fr; height:auto; min-height:104px; gap:4px; }} .kv {{ grid-template-columns:1fr; }} }}
    .csf-explorer-composite {{ grid-template-rows:auto auto minmax(0,1fr); overflow:hidden; }} .csf-explorer-section {{ min-height:0; }} .csf-explorer-section + .csf-explorer-section {{ padding-top:10px; border-top:1px solid rgba(34,50,59,.10); }} .csf-explorer-composite .csf-selection-list {{ display:grid; grid-template-rows:auto minmax(0,1fr); overflow:hidden; }} .csf-example-region {{ overflow:auto; overscroll-behavior:contain; }} .csf-example-region .csf-outcome-state {{ padding:6px 14px 12px; color:var(--muted); font-size:13px; }} .csf-example-region .csf-outcome-state > :first-child {{ margin-top:0; }} .csf-example-region .csf-outcome-state > :last-child {{ margin-bottom:0; }} .workspace-scroll.csf-explorer-workspace {{ display:grid; grid-template-columns:minmax(0,1fr); grid-template-rows:repeat(2,minmax(0,1fr)); gap:18px; }} .workspace-scroll.csf-explorer-workspace > * + * {{ margin-top:0; }} @media (min-width:1000px) {{ .workspace-scroll .csf-explorer-composite > .csf-selection-list:first-child {{ height:116px; grid-template-rows:18px 98px; }} .workspace-scroll .csf-explorer-composite > .csf-selection-list:first-child .kicker {{ margin-bottom:0; line-height:18px; }} .workspace-scroll .csf-explorer-composite > .csf-selection-list:nth-child(2) {{ height:127px; grid-template-rows:18px 98px; }} .workspace-scroll .csf-explorer-composite > .csf-selection-list:nth-child(2) .kicker {{ margin-bottom:0; line-height:18px; }} .workspace-scroll .csf-selection-list .csf-explorer-list[data-explorer-list="categories"] {{ grid-auto-rows:95px; height:95px; max-height:95px; margin-top:3px; }} .csf-explorer-list[data-explorer-list="categories"] .csf-explorer-row {{ height:95px; }} .workspace-scroll .csf-selection-list .csf-explorer-list[data-explorer-list="subcategories"] {{ grid-auto-rows:95px; height:95px; max-height:95px; margin-top:3px; }} .csf-explorer-list[data-explorer-list="subcategories"] .csf-explorer-row {{ height:95px; }} }} @media (min-width:1000px) and (max-height:999px) {{ .workspace-scroll.csf-explorer-workspace {{ grid-template-rows:repeat(2,534px); }} .workspace-scroll.csf-explorer-workspace > .csf-explorer {{ height:534px; min-height:0; }} .workspace-scroll.csf-explorer-workspace > .csf-explorer:not(.csf-explorer-composite) {{ overflow:auto; overscroll-behavior:contain; }} }} @media (min-width:1000px) and (min-height:1000px) {{ .workspace-scroll.csf-explorer-workspace {{ grid-template-rows:repeat(2,minmax(0,1fr)); grid-auto-rows:unset; }} .workspace-scroll.csf-explorer-workspace > .csf-explorer-composite {{ grid-row:auto; min-height:0; grid-template-rows:116px 127px minmax(0,1fr); overflow:hidden !important; }} }}
    #csf-evidence-workspace-title {{ margin-bottom:0; line-height:18px; }} .csf-explorer.csf-evidence-workspace {{ align-content:start; gap:3px; }} .csf-assessment-prototype {{ display:grid; gap:6px; }} .csf-assessment-prototype > .kicker {{ margin:0; }} .csf-assessment-context {{ display:grid; gap:4px; }} .csf-assessment-context > .mini {{ margin:0; }} .csf-assessment-example {{ padding:8px 10px; border-left:3px solid rgba(125,163,143,.58); background:rgba(232,240,234,.48); }} .csf-assessment-example p,.csf-assessment-example ul {{ margin:0; color:var(--muted); font-size:13px; }} .csf-assessment-example ul {{ padding-left:18px; }} .csf-assessment-block {{ padding:11px 13px; border:1px solid rgba(34,50,59,.10); border-radius:12px; background:rgba(255,255,255,.76); }} .csf-assessment-block strong {{ display:block; margin-bottom:4px; font-size:12px; text-transform:uppercase; letter-spacing:.08em; color:#475861; }} .csf-assessment-block p {{ margin:0; color:var(--muted); font-size:13px; }} .csf-assessment-comparison {{ display:grid; grid-template-columns:repeat(2,minmax(0,1fr)); gap:8px; }} .csf-assessment-comparison .csf-assessment-block {{ min-width:0; }} .csf-response-options {{ display:flex; flex-wrap:wrap; gap:7px; margin:7px 0; }} .csf-response-options .csf-assessment-choice {{ padding:4px 8px; border:1px solid rgba(34,50,59,.14); border-radius:999px; color:#53636b; font:inherit; font-size:12px; background:rgba(255,255,255,.82); cursor:pointer; }} .csf-response-options .csf-assessment-choice:hover {{ border-color:rgba(93,127,148,.56); }} .csf-response-options .csf-assessment-choice.active {{ color:#315345; border-color:rgba(125,163,143,.60); background:var(--sage-soft); font-weight:700; }} .csf-profile-assessment .csf-assessment-choice:disabled {{ cursor:default; opacity:1; }} .csf-record-list {{ display:grid; gap:6px; height:72px; overflow:auto; padding-right:4px; }} .csf-record-list-head {{ display:flex; align-items:center; justify-content:space-between; gap:8px; }} .csf-record-list-head strong {{ margin:0; }} .csf-add-record {{ display:grid; place-items:center; width:24px; height:24px; border:1px solid rgba(93,127,148,.45); border-radius:50%; color:#315345; font-size:19px; line-height:1; text-decoration:none; }} .csf-add-record:hover {{ background:var(--sage-soft); }} .csf-record-row {{ display:grid; gap:2px; padding:8px 10px; border:1px solid rgba(34,50,59,.10); border-radius:10px; background:rgba(255,255,255,.68); color:var(--ink); text-decoration:none; }} .csf-record-row:hover {{ background:var(--blue-soft); }} .csf-record-row span {{ color:var(--muted); font-size:12px; }} .csf-record-empty {{ margin:0; color:var(--muted); font-size:13px; }} .csf-community-profile-list {{ display:grid; gap:0; }} .csf-community-profile-row {{ display:grid; gap:2px; padding:7px 0; border-bottom:1px solid rgba(34,50,59,.10); color:var(--ink); text-decoration:none; }} .csf-community-profile-row:first-child {{ border-top:1px solid rgba(34,50,59,.10); }} .csf-community-profile-row strong {{ font-size:13px; }} .csf-community-profile-row span {{ color:var(--muted); font-size:12px; }} .csf-community-profile-row:hover {{ color:#315345; background:rgba(232,240,234,.36); }} .csf-entry-form {{ display:grid; gap:12px; }} .csf-entry-form label {{ display:grid; gap:4px; color:#475861; font-size:13px; font-weight:700; }} .csf-entry-form input,.csf-entry-form select,.csf-entry-form textarea {{ width:100%; box-sizing:border-box; padding:8px 10px; border:1px solid rgba(34,50,59,.18); border-radius:8px; background:#fff; font:inherit; font-weight:400; }} .csf-entry-form textarea {{ min-height:76px; resize:vertical; }} .csf-entry-form .mini {{ margin:0; }} @media (max-width:560px) {{ .csf-assessment-comparison {{ grid-template-columns:1fr; }} }}
    .csf-record-list {{ grid-auto-rows:56px; height:56px; scroll-snap-type:y mandatory; }} .csf-record-row {{ height:56px; box-sizing:border-box; overflow:hidden; scroll-snap-align:start; }} .csf-profile-picker-list.csf-record-list {{ display:grid; gap:0; grid-auto-rows:32px; height:160px !important; max-height:160px !important; padding:0; border:1px solid rgba(34,50,59,.12); border-radius:8px; background:rgba(255,255,255,.55); }} .csf-profile-choice {{ display:flex; align-items:center; height:32px; box-sizing:border-box; padding:0 10px; color:var(--ink); cursor:pointer; scroll-snap-align:start; }} .csf-profile-choice + .csf-profile-choice {{ border-top:1px solid rgba(34,50,59,.08); }} .csf-profile-choice input[type="radio"] {{ position:absolute; inline-size:1px; block-size:1px; opacity:0; }} .csf-profile-choice:has(input:checked) {{ box-shadow:inset 3px 0 0 #7da38f; background:var(--sage-soft); color:#315345; font-weight:700; }} .csf-profile-choice:has(input:focus-visible) {{ outline:2px solid rgba(135,169,194,.72); outline-offset:-2px; }} .csf-add-record {{ width:auto; height:auto; border:0; border-radius:0; background:transparent; font-weight:700; }} .csf-add-record:hover {{ background:transparent; color:#1e4c3a; }} .modal-head-actions {{ display:flex; align-items:center; gap:14px; flex:none; }} .modal-head-actions .csf-add-record {{ font-size:24px; line-height:1; }} .csf-status-options {{ display:flex; flex-wrap:wrap; gap:7px; margin:0; padding:0; border:0; }} .csf-status-options legend {{ width:100%; margin-bottom:4px; color:#475861; font-size:13px; font-weight:700; }} .csf-status-choice {{ display:flex !important; align-items:center; gap:5px; padding:4px 8px; border:1px solid rgba(34,50,59,.14); border-radius:999px; color:#53636b !important; font-weight:400 !important; }} .csf-status-choice:has(input:checked) {{ color:#315345 !important; border-color:rgba(125,163,143,.60); background:var(--sage-soft); font-weight:700 !important; }} .csf-status-choice input {{ width:auto !important; margin:0; }} .modal-head {{ padding:14px 18px; }} .modal-head > div {{ min-width:0; }} .csf-modal-outcome {{ max-width:680px; margin:2px 0 0; font-size:17px; line-height:1.25; }} .csf-modal-target-context {{ display:grid; gap:3px; margin-top:8px; padding:7px 9px; border-left:3px solid #7da38f; border-radius:6px; background:rgba(232,240,234,.56); color:#475861; font-size:12px; line-height:1.35; }} .csf-modal-target-context strong {{ color:#315345; }} .modal-body {{ padding:14px 18px; }} .csf-entry-form {{ gap:8px; }} .csf-entry-form textarea {{ min-height:62px; }} .csf-linked-control {{ display:grid; gap:3px; padding:8px 10px; border:1px solid rgba(93,127,148,.32); border-left:3px solid #5d7f94; border-radius:8px; background:rgba(232,239,245,.54); color:#42555f; font-size:12px; }} .csf-linked-control strong {{ color:#41525a; font-size:12px; text-transform:uppercase; letter-spacing:.05em; }} .csf-linked-control.manual {{ border-left-color:#9b8a76; background:rgba(248,245,239,.72); }}
    .csf-control-picker {{ display:grid; gap:7px; margin:0; padding:11px; border:1px solid rgba(34,50,59,.14); border-radius:10px; }} .csf-control-picker legend {{ padding:0 3px; color:#475861; font-size:13px; font-weight:700; }} .csf-control-picker legend span {{ color:var(--muted); font-weight:400; }} .csf-control-picker .mini {{ margin:0; }} .csf-control-list {{ display:grid; gap:6px; max-height:246px; overflow:auto; padding-right:4px; }} .csf-mapped-control-list,.csf-action-evidence-list {{ max-height:100px; }} .csf-control-choice {{ display:grid !important; grid-template-columns:auto minmax(0,1fr); align-items:start; gap:9px; padding:9px 10px; border:1px solid rgba(34,50,59,.12); border-radius:8px; background:rgba(255,255,255,.68); cursor:pointer; }} .csf-control-choice > input {{ width:auto !important; margin:3px 0 0 !important; }} .csf-control-content {{ display:grid; gap:3px; min-width:0; color:var(--muted); font-weight:400; }} .csf-control-choice strong {{ color:var(--ink); font-size:12px; }} .csf-control-title {{ color:#53636b; font-size:12px; }} .csf-control-interpretation,.csf-control-action {{ margin:3px 0 0; color:#586a73; font-size:12px; line-height:1.38; }} .csf-control-action {{ color:#456557; }} .csf-control-interpretation b,.csf-control-action b {{ color:#41525a; }} .csf-control-official {{ margin-top:3px; color:var(--muted); font-size:11px; }} .csf-control-official summary {{ cursor:pointer; color:#4f6c7e; }} .csf-control-official p {{ margin:5px 0 0; line-height:1.38; }} .csf-control-choice small {{ color:#7b6a61; font-size:11px; }} .csf-control-choice:has(input:checked) {{ border-color:rgba(125,163,143,.60); background:var(--sage-soft); }} .csf-control-choice.unavailable {{ opacity:.48; cursor:not-allowed; background:rgba(235,232,226,.72); }}
    .csf-why-matters {{ display:flex; align-items:center; justify-content:space-between; gap:12px; padding:8px 10px; border-left:3px solid rgba(93,127,148,.60); background:rgba(232,239,245,.55); }} .csf-why-matters .kicker {{ margin:0 0 2px; }} .csf-why-matters p {{ margin:0; color:#4b606b; font-size:13px; line-height:1.45; }} .csf-information-flow-button {{ flex:none; padding:6px 9px; border:1px solid rgba(93,127,148,.40); border-radius:999px; background:rgba(255,255,255,.76); color:#38586b; font:inherit; font-size:12px; font-weight:700; cursor:pointer; }} .csf-information-flow-button:hover {{ background:var(--blue-soft); }} .csf-information-flow-dialog {{ width:min(1080px,100%); }} .csf-information-flow-body {{ display:grid; gap:14px; }} .csf-information-flow-body section {{ display:grid; gap:7px; }} .csf-information-flow-body h3 {{ margin:0; }} .csf-flow-graph {{ display:grid; grid-template-columns:minmax(140px,.85fr) 62px minmax(180px,1fr) 62px minmax(240px,1.45fr); align-items:center; gap:8px; padding:10px; border:1px solid rgba(34,50,59,.10); border-radius:14px; background:rgba(248,245,239,.52); }} .csf-flow-node,.csf-flow-consumer {{ display:grid; gap:2px; padding:8px; border:1px solid rgba(34,50,59,.12); border-radius:10px; background:rgba(255,255,255,.78); }} .csf-flow-node.source {{ border-left:3px solid #5d7f94; }} .csf-flow-node.information {{ border-left:3px solid #7da38f; background:var(--sage-soft); }} .csf-flow-node strong,.csf-flow-consumer strong {{ font-size:12px; line-height:1.25; }} .csf-flow-node span,.csf-flow-consumer span,.csf-flow-consumer p {{ margin:0; color:var(--muted); font-size:11px; line-height:1.25; }} .csf-flow-consumers {{ display:grid; gap:4px; }} .csf-flow-consumer {{ padding:5px 8px; }} .csf-flow-consumer span {{ color:#456557; font-weight:700; text-transform:uppercase; letter-spacing:.05em; }} .csf-flow-consumer p {{ display:-webkit-box; overflow:hidden; -webkit-box-orient:vertical; -webkit-line-clamp:2; }} .csf-flow-arrow {{ display:grid; grid-template-columns:auto 1fr; align-items:center; gap:4px; color:#648072; font-size:11px; white-space:nowrap; }} .csf-flow-arrow b {{ font-size:22px; line-height:1; font-weight:500; }} @media (max-width:760px) {{ .csf-why-matters {{ align-items:flex-start; flex-direction:column; }} .csf-flow-graph,.csf-flow-graph.input {{ grid-template-columns:1fr; }} .csf-flow-arrow {{ grid-template-columns:auto auto; }} .csf-flow-arrow b {{ transform:rotate(90deg); justify-self:start; }} }}
    .csf-assessment-inline {{ display:flex; align-items:center; gap:8px; min-width:0; }} .csf-assessment-inline > strong {{ flex:none; margin:0; }} .csf-assessment-inline form {{ min-width:0; }} .csf-assessment-inline .csf-response-options {{ margin:0; }} .csf-information-flow-buttons {{ display:flex; flex:none; flex-wrap:wrap; gap:6px; justify-content:flex-end; }}
    .csf-explorer-composite.csf-function-govern {{ --csf-workspace-color:#f9f49d; --csf-workspace-ink:#3b3b1f; }} .csf-explorer-composite.csf-function-identify {{ --csf-workspace-color:#4bb2e0; --csf-workspace-ink:#163b4d; }} .csf-explorer-composite.csf-function-protect {{ --csf-workspace-color:#9292ea; --csf-workspace-ink:#292957; }} .csf-explorer-composite.csf-function-detect {{ --csf-workspace-color:#fab746; --csf-workspace-ink:#563914; }} .csf-explorer-composite.csf-function-respond {{ --csf-workspace-color:#f97367; --csf-workspace-ink:#5a2722; }} .csf-explorer-composite.csf-function-recover {{ --csf-workspace-color:#7df49f; --csf-workspace-ink:#1d4c2b; }} .csf-explorer-composite[class*="csf-function-"] .csf-explorer-row {{ background:color-mix(in srgb,var(--csf-workspace-color) 9%,white); border-color:color-mix(in srgb,var(--csf-workspace-color) 38%,#cbd0cc); }} .csf-explorer-composite[class*="csf-function-"] .csf-explorer-row:hover {{ background:color-mix(in srgb,var(--csf-workspace-color) 17%,white); border-color:color-mix(in srgb,var(--csf-workspace-color) 72%,#a7a9a7); }} .csf-explorer-composite[class*="csf-function-"] .csf-explorer-row.active {{ background:color-mix(in srgb,var(--csf-workspace-color) 22%,white); border-color:color-mix(in srgb,var(--csf-workspace-color) 72%,#a7a9a7); box-shadow:inset 4px 0 0 var(--csf-workspace-color); }} .csf-explorer-composite[class*="csf-function-"] .csf-explorer-id,.csf-explorer-composite[class*="csf-function-"] .kicker {{ color:var(--csf-workspace-ink); }}
    .csf-guidance.csf-function-govern {{ --csf-guidance-color:#f9f49d; --csf-guidance-ink:#3b3b1f; }} .csf-guidance.csf-function-identify {{ --csf-guidance-color:#4bb2e0; --csf-guidance-ink:#163b4d; }} .csf-guidance.csf-function-protect {{ --csf-guidance-color:#9292ea; --csf-guidance-ink:#292957; }} .csf-guidance.csf-function-detect {{ --csf-guidance-color:#fab746; --csf-guidance-ink:#563914; }} .csf-guidance.csf-function-respond {{ --csf-guidance-color:#f97367; --csf-guidance-ink:#5a2722; }} .csf-guidance.csf-function-recover {{ --csf-guidance-color:#7df49f; --csf-guidance-ink:#1d4c2b; }} .csf-guidance[class*="csf-function-"] {{ background:color-mix(in srgb,var(--csf-guidance-color) 24%,white); border-color:color-mix(in srgb,var(--csf-guidance-color) 72%,#a7a9a7); color:var(--csf-guidance-ink); }} .csf-guidance[class*="csf-function-"] strong {{ color:var(--csf-guidance-ink); }}
  </style>
</head>
<body>
  <div class="shell"><div class="page-stack">{body}</div></div>
  <div id="csf-modal-host"></div>
  {UI_CLIENT_SCRIPT}
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
    indicator_export_path: Path
    protection_profile: str
    ui_persona: str
    repo_root: Path
    app_mode: str = "analyst"


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
        "display_name": "CSF Analyst",
        "description": "Single guided CSF experience for interpreting evidence, reviewing risk, and preserving decisions without changing a user's authority.",
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
    return dict(catalog.get(CSF_ANALYST_PERSONA_ID) or DEFAULT_PERSONA_PROFILES[CSF_ANALYST_PERSONA_ID])


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


def load_settings(settings_path: Path, app_mode: str = "monitoring") -> AppConfig:
    repo_root = Path(__file__).resolve().parent
    settings = {}
    if settings_path.exists():
        settings = parse_json(settings_path)

    settings_dir = settings_path.resolve().parent
    runtime_root = resolve_settings_path(settings_dir, settings.get("RuntimeRoot"), settings_dir)
    data_root = resolve_settings_path(settings_dir, settings.get("DataRoot"), runtime_root)
    state_db_setting = (
        settings.get("AnalystStateDbPath")
        if app_mode == "analyst"
        else settings.get("MonitorStateDbPath") or settings.get("StateDbPath")
    )
    state_db_default = data_root / "state" / ("csf-analyst.db" if app_mode == "analyst" else "codex-monitoring.db")
    state_db_path = resolve_settings_path(settings_dir, state_db_setting, state_db_default)
    indicator_export_path = resolve_settings_path(settings_dir, settings.get("IndicatorExportPath"), data_root / "indicators" / "feed-indicators-latest.json")
    protection_profile = str(settings.get("ProtectionProfile") or "microsoft_baseline")
    persona_profiles = load_persona_profiles(repo_root)
    ui_persona = CSF_ANALYST_PERSONA_ID

    return AppConfig(
        settings_path=settings_path.resolve(),
        runtime_root=runtime_root,
        data_root=data_root,
        state_db_path=state_db_path,
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
    requested = str(persona_id or "").strip().lower()
    if requested and requested != CSF_ANALYST_PERSONA_ID:
        raise RuntimeError("The management UI uses the single CSF Analyst workflow; persona switching is no longer available.")
    config.ui_persona = CSF_ANALYST_PERSONA_ID
    return "CSF Analyst workflow is active."


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


def list_sqlite_alerts(state_db_path: Path, limit: int = 50) -> List[Dict[str, Any]]:
    if not state_db_path.is_file():
        return []
    try:
        connection = sqlite3.connect(f"file:{state_db_path.resolve()}?mode=ro", uri=True)
        connection.row_factory = sqlite3.Row
        try:
            records = ioc_store.list_persisted_alerts(connection, limit=limit)
            for record in records:
                record["title"] = record.get("summary") or record.get("alert_id") or "SQLite alert"
                record["message"] = record.get("summary") or ""
                record["collection_time"] = record.get("created_at") or ""
                record["change_count"] = None
            return records
        finally:
            connection.close()
    except (OSError, sqlite3.Error, ValueError):
        return []


def list_sqlite_csf_guidance(state_db_path: Path, language_code: str = "en-US") -> Dict[str, str]:
    if not state_db_path.is_file(): return {}
    try:
        connection = sqlite3.connect(f"file:{state_db_path.resolve()}?mode=ro", uri=True); connection.row_factory = sqlite3.Row
        try:
            rows = connection.execute("SELECT subcategory_id, plain_english_text FROM csf_subcategory_guidance WHERE language_code = ?", (language_code,)).fetchall()
            return {str(row["subcategory_id"]): str(row["plain_english_text"]) for row in rows}
        finally: connection.close()
    except (OSError, sqlite3.Error, ValueError): return {}

def list_sqlite_csf_product_examples(state_db_path: Path, language_code: str = "en-US") -> Dict[str, Dict[str, Any]]:
    if not state_db_path.is_file(): return {}
    try:
        connection = sqlite3.connect(f"file:{state_db_path.resolve()}?mode=ro", uri=True); connection.row_factory = sqlite3.Row
        try:
            rows = connection.execute("SELECT subcategory_id, examples_json FROM csf_subcategory_guidance WHERE language_code = ?", (language_code,)).fetchall()
            return {str(row["subcategory_id"]): {"examples": json.loads(row["examples_json"] or "[]")} for row in rows}
        finally: connection.close()
    except (OSError, sqlite3.Error, ValueError, json.JSONDecodeError): return {}

def list_sqlite_csf_generic_action_examples(state_db_path: Path, language_code: str = "en-US") -> Dict[str, Dict[str, str]]:
    if not state_db_path.is_file(): return {}
    try:
        connection = sqlite3.connect(f"file:{state_db_path.resolve()}?mode=ro", uri=True); connection.row_factory = sqlite3.Row
        try:
            rows = connection.execute("SELECT subcategory_id, generic_action_title, generic_action_details, generic_action_rationale FROM csf_subcategory_guidance WHERE language_code = ?", (language_code,)).fetchall()
            return {str(row["subcategory_id"]): {"title": str(row["generic_action_title"] or ""), "details": str(row["generic_action_details"] or ""), "rationale": str(row["generic_action_rationale"] or "")} for row in rows}
        finally: connection.close()
    except (OSError, sqlite3.Error, ValueError): return {}


def list_sqlite_csf_profile_action_examples(state_db_path: Path, profile_id: str) -> Dict[str, Dict[str, str]]:
    """Read optional Profile-specific Add Action examples without changing state."""
    if not state_db_path.is_file() or not profile_id:
        return {}
    try:
        connection = sqlite3.connect(f"file:{state_db_path.resolve()}?mode=ro", uri=True)
        connection.row_factory = sqlite3.Row
        try:
            rows = connection.execute(
                """SELECT subcategory_id, action_title_example, action_details_example,
                          action_rationale_example
                FROM csf_profile_action_guidance WHERE profile_id = ?""",
                (profile_id,),
            ).fetchall()
            return {
                str(row["subcategory_id"]): {
                    "title": str(row["action_title_example"] or ""),
                    "details": str(row["action_details_example"] or ""),
                    "rationale": str(row["action_rationale_example"] or ""),
                }
                for row in rows
            }
        finally:
            connection.close()
    except (OSError, sqlite3.Error, ValueError):
        return {}


def list_sqlite_csf_profile_sample_opportunities(state_db_path: Path, profile_id: str) -> Dict[str, Dict[str, str]]:
    """Return the official, non-empty focus-area opportunities for one profile."""
    if not state_db_path.is_file() or not profile_id:
        return {}
    try:
        connection = sqlite3.connect(f"file:{state_db_path.resolve()}?mode=ro", uri=True)
        connection.row_factory = sqlite3.Row
        try:
            rows = connection.execute(
                """SELECT outcome_id, facet_label, opportunities
                FROM csf_community_profile_outcome_facets
                WHERE profile_id = ? AND trim(opportunities) <> ''
                  AND lower(trim(opportunities)) NOT IN (
                      'standard cybersecurity practices apply.',
                      'standard cybersecurity practices apply'
                  )
                ORDER BY outcome_id, facet_id""",
                (profile_id,),
            ).fetchall()
            return {
                str(row["outcome_id"]): {
                    "focus_area": str(row["facet_label"] or ""),
                    "text": str(row["opportunities"] or ""),
                }
                for row in rows
            }
        finally:
            connection.close()
    except (OSError, sqlite3.Error, ValueError):
        return {}


def merged_action_examples(generic: Dict[str, str], profile_specific: Dict[str, str]) -> Dict[str, str]:
    """Prefer non-empty Profile guidance while retaining generic CSF fallbacks."""
    return {
        field: str(profile_specific.get(field) or generic.get(field) or "")
        for field in ("title", "details", "rationale")
    }


def proposed_priority_label(value: Any) -> str:
    """Translate NIST IR 8596's numeric proposed-priority scale for display."""
    return {"1": "High", "2": "Moderate", "3": "Foundational"}.get(str(value or "").strip(), "")


def list_sqlite_csf_profile_metadata(state_db_path: Path, language_code: str = "en-US") -> Dict[str, Dict[str, Any]]:
    """Read generated Profile metadata without changing the state store."""
    if not state_db_path.is_file():
        return {}
    try:
        connection = sqlite3.connect(f"file:{state_db_path.resolve()}?mode=ro", uri=True)
        connection.row_factory = sqlite3.Row
        try:
            rows = connection.execute(
                """
                SELECT subcategory_id, assessment_method, research_guidance, supporting_note_required
                FROM csf_subcategory_profile_metadata
                WHERE language_code = ?
                ORDER BY subcategory_id
                """,
                (language_code,),
            ).fetchall()
            return {
                str(row["subcategory_id"]): {
                    "assessment_method": str(row["assessment_method"]),
                    "research_guidance": str(row["research_guidance"]),
                    "supporting_note_required": bool(row["supporting_note_required"]),
                }
                for row in rows
            }
        finally:
            connection.close()
    except (OSError, sqlite3.Error, ValueError):
        return {}


def list_sqlite_csf_current_assessments(state_db_path: Path, profile_id: str) -> Dict[str, Dict[str, Any]]:
    """Read the mutable current-assessment working records without touching audit history."""
    if not state_db_path.is_file():
        return {}
    try:
        connection = sqlite3.connect(f"file:{state_db_path.resolve()}?mode=ro", uri=True)
        connection.row_factory = sqlite3.Row
        try:
            return ioc_store.list_current_csf_assessments(connection, profile_id)
        finally:
            connection.close()
    except (OSError, sqlite3.Error, ValueError):
        return {}


def list_sqlite_csf_profile_targets(state_db_path: Path, profile_id: str) -> Dict[str, Dict[str, Any]]:
    """Read one active Profile's desired Tile 3 assessment levels."""
    if not state_db_path.is_file() or not profile_id:
        return {}
    try:
        connection = sqlite3.connect(f"file:{state_db_path.resolve()}?mode=ro", uri=True)
        connection.row_factory = sqlite3.Row
        try:
            return ioc_store.list_csf_profile_outcome_targets(connection, profile_id)
        finally:
            connection.close()
    except (OSError, sqlite3.Error, ValueError):
        return {}


def get_sqlite_csf_profile_context(state_db_path: Path) -> Dict[str, Any]:
    """Read the active Organizational Profile and the selector's defined options."""
    if not state_db_path.is_file():
        return {"active_profile": {}, "defined_profiles": [], "community_profiles": []}
    try:
        connection = sqlite3.connect(f"file:{state_db_path.resolve()}?mode=ro", uri=True)
        connection.row_factory = sqlite3.Row
        try:
            return {
                "active_profile": ioc_store.get_active_csf_profile(connection),
                "defined_profiles": ioc_store.list_csf_profile_definitions(connection),
                "community_profiles": ioc_store.list_csf_community_profiles(connection),
            }
        finally:
            connection.close()
    except (OSError, sqlite3.Error, ValueError):
        return {"active_profile": {}, "defined_profiles": [], "community_profiles": []}


def csf_profile_picker_label(profile: Dict[str, Any]) -> str:
    """Give each Profile a concise, visible type indicator in pickers."""
    kind = str(profile.get("profile_kind") or "organizational").strip().lower()
    prefix = {
        "organizational": "O",
        "frozen_community": "C",
        "frozen_base": "B",
    }.get(kind, "P")
    return f"{prefix} - {str(profile.get('profile_name') or '').strip()}"


def community_profile_catalog_label(profile: Dict[str, Any]) -> str:
    """Prefer the name of the locally imported frozen Profile artifact."""
    return str(
        profile.get("imported_profile_name")
        or profile.get("community_profile_name")
        or profile.get("profile_name")
        or ""
    ).strip()


def render_community_profile_summaries(profiles: List[Dict[str, Any]], *, link_to_source: bool = False) -> str:
    """Render the catalog metadata consistently wherever Community Profiles are listed."""
    rows = []
    for profile in profiles:
        details = " · ".join(
            value for value in (
                str(profile.get("publisher") or "").strip(),
                str(profile.get("publication_status") or "See source").strip(),
                str(profile.get("focus") or "").strip(),
            ) if value
        )
        source_details = " · ".join(
            value for value in (
                f"Source version: {str(profile.get('source_version') or profile.get('community_profile_source_version') or '').strip()}"
                if str(profile.get("source_version") or profile.get("community_profile_source_version") or "").strip() else "",
                f"Last source review: {str(profile.get('source_reviewed_at') or profile.get('community_profile_source_reviewed_at') or '').strip()}"
                if str(profile.get("source_reviewed_at") or profile.get("community_profile_source_reviewed_at") or "").strip() else "",
                f"Next source review: {str(profile.get('next_source_review_at') or profile.get('community_profile_next_source_review_at') or '').strip()}"
                if str(profile.get("next_source_review_at") or profile.get("community_profile_next_source_review_at") or "").strip() else "",
            ) if value
        )
        content = f'<strong>{esc(community_profile_catalog_label(profile))}</strong><span>{esc(details)}</span>'
        if source_details:
            content += f'<span>{esc(source_details)}</span>'
        if link_to_source:
            rows.append(
                f'<a class="csf-community-profile-row" href="{esc(str(profile.get("source_url") or ""))}" target="_blank" rel="noreferrer">{content}</a>'
            )
        else:
            rows.append(f'<div class="csf-community-profile-row">{content}</div>')
    return "".join(rows) or '<p class="csf-record-empty">No Community Profiles are in the local catalog.</p>'


def render_active_profile_source(active_profile: Dict[str, Any]) -> str:
    """Show the selected Profile's direct lineage without duplicating the catalog list."""
    active_kind = str(active_profile.get("profile_kind") or "").strip()
    if active_kind == "frozen_community" and active_profile.get("community_profile_id"):
        return render_community_profile_summaries([
            {
                "community_profile_name": active_profile.get("community_profile_name"),
                "publisher": active_profile.get("community_profile_publisher"),
                "publication_status": active_profile.get("community_profile_publication_status"),
                "focus": active_profile.get("community_profile_focus"),
                "community_profile_source_version": active_profile.get("community_profile_source_version"),
                "community_profile_source_reviewed_at": active_profile.get("community_profile_source_reviewed_at"),
                "community_profile_next_source_review_at": active_profile.get("community_profile_next_source_review_at"),
            }
        ])

    source_name = str(active_profile.get("source_profile_name") or "").strip()
    source_kind = str(active_profile.get("source_profile_kind") or "").strip()
    if source_name:
        kind_label = {
            "frozen_base": "NIST CSF base",
            "frozen_community": "Community Profile",
            "organizational": "Organizational Profile copy",
        }.get(source_kind, "Profile source")
        source_details = kind_label
        if source_kind == "frozen_community":
            source_details += " · " + " · ".join(
                value for value in (
                    str(active_profile.get("community_profile_publisher") or "").strip(),
                    str(active_profile.get("community_profile_publication_status") or "").strip(),
                    str(active_profile.get("community_profile_focus") or "").strip(),
                ) if value
            )
            version = str(active_profile.get("community_profile_source_version") or "").strip()
            reviewed_at = str(active_profile.get("community_profile_source_reviewed_at") or "").strip()
            next_review_at = str(active_profile.get("community_profile_next_source_review_at") or "").strip()
            provenance = " · ".join(
                value for value in (
                    f"Source version: {version}" if version else "",
                    f"Last source review: {reviewed_at}" if reviewed_at else "",
                    f"Next source review: {next_review_at}" if next_review_at else "",
                ) if value
            )
            if provenance:
                source_details += " · " + provenance
        return (
            '<div class="csf-community-profile-row">'
            f'<strong>{esc(source_name)}</strong><span>{esc(source_details)}</span></div>'
        )
    return '<p class="csf-record-empty">No source profile is recorded.</p>'


def render_active_profile_controls(state_db_path: Path, profile_id: Any) -> str:
    """Describe the control catalogs enabled for the selected Profile."""
    if not state_db_path.is_file() or not str(profile_id or "").strip():
        return '<div class="mini"><strong>Controls:</strong> No control catalog is enabled for this Profile.</div>'
    try:
        connection = sqlite3.connect(f"file:{state_db_path.resolve()}?mode=ro", uri=True)
        connection.row_factory = sqlite3.Row
        try:
            catalogs = ioc_store.list_csf_profile_control_catalogs(connection, profile_id)
        finally:
            connection.close()
    except (OSError, sqlite3.Error, ValueError):
        catalogs = []
    enabled = [catalog for catalog in catalogs if int(catalog.get("profile_is_enabled") or 0)]
    if not enabled:
        return (
            '<div class="mini"><strong>Controls:</strong> No control catalog is enabled for this Profile. '
            'Actions will use outcome-specific examples without mapped control guidance.</div>'
        )
    names = [
        " ".join(part for part in (str(catalog.get("display_name") or "").strip(), str(catalog.get("version") or "").strip()) if part)
        for catalog in enabled
    ]
    return (
        '<div class="mini"><strong>Controls:</strong> '
        f'{esc(", ".join(names))} {"is" if len(names) == 1 else "are"} enabled. '
        'Mapped controls are available in the Add Action picker.</div>'
    )


def list_sqlite_csf_profile_scope(state_db_path: Path, profile_name: str) -> Dict[str, str]:
    """Return the active Profile's explicit inclusion status for each outcome."""
    if not state_db_path.is_file() or not profile_name:
        return {}
    try:
        connection = sqlite3.connect(f"file:{state_db_path.resolve()}?mode=ro", uri=True)
        connection.row_factory = sqlite3.Row
        try:
            return {
                str(row["outcome_id"]): str(row["profile_status"])
                for row in ioc_store.list_csf_profile_outcomes(connection, profile_name)
            }
        finally:
            connection.close()
    except (OSError, sqlite3.Error, ValueError):
        return {}


def list_sqlite_csf_community_profile_guidance(state_db_path: Path, profile_id: str) -> Dict[str, Dict[str, str]]:
    """Return official application notes only when a frozen Community Profile is active."""
    if not state_db_path.is_file() or not profile_id:
        return {}
    try:
        connection = sqlite3.connect(f"file:{state_db_path.resolve()}?mode=ro", uri=True)
        connection.row_factory = sqlite3.Row
        try:
            rows = connection.execute(
                """SELECT outcome.outcome_id, outcome.notes, outcome.considerations
                FROM csf_profiles outcome
                JOIN csf_profile_definitions definition ON definition.profile_name = outcome.profile_name
                WHERE definition.profile_id = ? AND definition.profile_kind = 'frozen_community'
                  AND outcome.profile_status = 'included' AND trim(outcome.notes) <> ''""",
                (profile_id,),
            ).fetchall()
            return {str(row["outcome_id"]): {"note": str(row["notes"]), "source": str(row["considerations"])} for row in rows}
        finally:
            connection.close()
    except (OSError, sqlite3.Error, ValueError):
        return {}


def list_sqlite_csf_outcome_records(state_db_path: Path, profile_id: str, subcategory_id: str) -> Dict[str, Any]:
    """Read the two mutable Tile 3 record lists for one official outcome."""
    if not state_db_path.is_file() or not str(subcategory_id or "").strip():
        return {"reviewed_actions": [], "supporting_basis": [], "read_error": ""}
    try:
        connection = sqlite3.connect(f"file:{state_db_path.resolve()}?mode=ro", uri=True)
        connection.row_factory = sqlite3.Row
        try:
            return {
                "reviewed_actions": ioc_store.list_csf_reviewed_actions(connection, profile_id, subcategory_id),
                "reviewed_action_total": int(connection.execute("SELECT COUNT(*) FROM csf_reviewed_actions WHERE profile_id = ?", (profile_id,)).fetchone()[0]),
                "mapped_controls": ioc_store.list_csf_mapped_controls_for_subcategory(connection, profile_id, subcategory_id),
                "enabled_control_catalog_count": int(connection.execute(
                    "SELECT COUNT(*) FROM csf_profile_control_catalogs WHERE profile_id = ? AND is_enabled = 1",
                    (profile_id,),
                ).fetchone()[0]),
                "supporting_basis": ioc_store.list_csf_supporting_basis(connection, profile_id, subcategory_id),
                "evidence_library": ioc_store.list_csf_evidence_library(connection, profile_id),
            }
        finally:
            connection.close()
    except (OSError, sqlite3.Error, ValueError) as exc:
        return {"reviewed_actions": [], "supporting_basis": [], "read_error": str(exc)}


def get_sqlite_csf_information_flow(state_db_path: Path, subcategory_id: str) -> Dict[str, List[Dict[str, Any]]]:
    """Return the one-hop, product-authored information flow for a CSF outcome.

    This is deliberately read-only.  The underlying flow catalog is seeded as a
    separate foundation from the control mappings and is never changed by this UI.
    """
    subcategory = str(subcategory_id or "").strip().upper()
    empty = {"inputs": [], "outputs": []}
    if not state_db_path.is_file() or not subcategory:
        return empty
    try:
        connection = sqlite3.connect(f"file:{state_db_path.resolve()}?mode=ro", uri=True)
        connection.row_factory = sqlite3.Row
        try:
            input_rows = connection.execute(
                """
                SELECT item.information_id, item.title, item.description,
                       use.dependency_kind, use.use_reason,
                       source.source_subcategory_id, source.source_guidance
                FROM csf_subcategory_information_uses AS use
                JOIN csf_information_items AS item ON item.information_id = use.information_id
                LEFT JOIN csf_subcategory_information_sources AS source ON source.information_id = item.information_id
                WHERE use.consumer_subcategory_id = ?
                ORDER BY item.title, source.source_subcategory_id
                """,
                (subcategory,),
            ).fetchall()
            output_rows = connection.execute(
                """
                SELECT item.information_id, item.title, item.description,
                       source.source_guidance, use.consumer_subcategory_id,
                       use.dependency_kind, use.use_reason
                FROM csf_subcategory_information_sources AS source
                JOIN csf_information_items AS item ON item.information_id = source.information_id
                LEFT JOIN csf_subcategory_information_uses AS use ON use.information_id = item.information_id
                WHERE source.source_subcategory_id = ?
                ORDER BY item.title, use.dependency_kind, use.consumer_subcategory_id
                """,
                (subcategory,),
            ).fetchall()

            inputs: Dict[str, Dict[str, Any]] = {}
            for row in input_rows:
                item = inputs.setdefault(str(row["information_id"]), {
                    "information_id": str(row["information_id"]), "title": str(row["title"]),
                    "description": str(row["description"]), "dependency_kind": str(row["dependency_kind"]),
                    "use_reason": str(row["use_reason"]), "sources": [],
                })
                if row["source_subcategory_id"]:
                    item["sources"].append({"subcategory_id": str(row["source_subcategory_id"]), "guidance": str(row["source_guidance"] or "")})
            outputs: Dict[str, Dict[str, Any]] = {}
            for row in output_rows:
                item = outputs.setdefault(str(row["information_id"]), {
                    "information_id": str(row["information_id"]), "title": str(row["title"]),
                    "description": str(row["description"]), "source_guidance": str(row["source_guidance"] or ""), "uses": [],
                })
                if row["consumer_subcategory_id"]:
                    item["uses"].append({"subcategory_id": str(row["consumer_subcategory_id"]), "dependency_kind": str(row["dependency_kind"]), "reason": str(row["use_reason"] or "")})
            return {"inputs": list(inputs.values()), "outputs": list(outputs.values())}
        finally:
            connection.close()
    except (OSError, sqlite3.Error, ValueError):
        return empty


def get_sqlite_alert_detail(state_db_path: Path, alert_id: str) -> Dict[str, Any]:
    if not state_db_path.is_file() or not str(alert_id or "").strip():
        return {"found": False, "alert": None}
    try:
        connection = sqlite3.connect(f"file:{state_db_path.resolve()}?mode=ro", uri=True)
        connection.row_factory = sqlite3.Row
        try:
            return ioc_store.get_persisted_alert(connection, alert_id)
        finally:
            connection.close()
    except (OSError, sqlite3.Error, ValueError):
        return {"found": False, "alert": None}


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


def list_sqlite_reports_preview(state_db_path: Path, limit: int = 15) -> List[Dict[str, Any]]:
    """Inactive Phase 3 adapter; callers must explicitly opt in after Phase 2 parity validation."""
    if not state_db_path.is_file():
        return []
    try:
        connection = sqlite3.connect(f"file:{state_db_path.resolve()}?mode=ro", uri=True)
        connection.row_factory = sqlite3.Row
        try:
            return ioc_store.list_persisted_reports(connection, limit=limit)
        finally:
            connection.close()
    except (OSError, sqlite3.Error, ValueError):
        return []


def get_sqlite_report_detail_preview(state_db_path: Path, report_id: str) -> Dict[str, Any]:
    """Inactive Phase 3 detail adapter; it is intentionally not wired to /report yet."""
    if not state_db_path.is_file() or not str(report_id or "").strip():
        return {"found": False, "report": None, "findings": []}
    try:
        connection = sqlite3.connect(f"file:{state_db_path.resolve()}?mode=ro", uri=True)
        connection.row_factory = sqlite3.Row
        try:
            return ioc_store.get_persisted_report(connection, report_id)
        finally:
            connection.close()
    except (OSError, sqlite3.Error, ValueError):
        return {"found": False, "report": None, "findings": []}


def build_sqlite_report_href(report_id: str) -> str:
    return f"/report?id={urllib.parse.quote(str(report_id or ''), safe='')}"


def render_sqlite_report_preview_row(report: Dict[str, Any]) -> str:
    summary = report.get("summary") or {}
    text = ", ".join(f"{key}={value}" for key, value in summary.items() if value not in (None, "", 0)) or "No summary fields"
    return f'<tr><td><a data-record-modal href="{esc(build_sqlite_report_href(str(report.get("report_id") or "")))}">{esc(report.get("name") or report.get("report_id"))}</a></td><td>{esc(report.get("report_type"))}</td><td>{esc(pretty_time(report.get("collection_time") or ""))}</td><td>{esc(text)}</td></tr>'


def build_sqlite_finding_acceptance_preview(finding_id: str) -> Dict[str, Any]:
    """Inactive Phase 3 contract; live acceptance remains path/index based until cutover approval."""
    return {"finding_id": str(finding_id or "").strip(), "requires_exact_finding_id": True, "live_action_enabled": False}


def resolve_inactive_sqlite_report_route(state_db_path: Path, report_id: str) -> Dict[str, Any]:
    return get_sqlite_report_detail_preview(state_db_path, report_id)


def render_sqlite_finding_preview(finding: Dict[str, Any]) -> str:
    return f'<article class="finding"><h4>{esc(finding.get("title") or "Finding")}</h4><div>{esc(finding.get("severity") or "Unknown")}</div><div>{esc(finding.get("summary") or "")}</div></article>'


def render_sqlite_report_detail_preview(detail: Dict[str, Any]) -> str:
    report = detail.get("report") or {}
    findings = "".join(render_sqlite_finding_preview(item) for item in detail.get("findings") or []) or "<p>No findings.</p>"
    return f'<section class="panel"><h2>{esc(report.get("report_id") or "Report")}</h2><div>{esc(report.get("report_type") or "")}</div>{findings}</section>'


def build_sqlite_finding_acceptance_command_preview(finding: Dict[str, Any]) -> Dict[str, Any]:
    finding_id = str(finding.get("finding_id") or "").strip()
    protected = str(finding.get("guardrail_state") or "").lower() == "protected"
    exact = bool(finding_id)
    return {"finding_id": finding_id, "requires_exact_finding_id": True, "live_action_enabled": False, "eligible": exact and not protected, "reason": "guardrail-protected" if protected else ("ready-for-future-cutover" if exact else "missing-finding-id")}


def find_latest_tripwire_check_report(config: AppConfig, snapshot: Dict[str, Any]) -> Optional[Path]:
    latest_artifact = ((snapshot.get("status") or {}).get("LatestArtifacts") or {}).get("LatestTripwireReport") or {}
    candidate = safe_path(str(latest_artifact.get("Path") or ""), [config.runtime_root])
    if candidate and candidate.name.upper().startswith("HOST_TRIPWIRE_CHECK_") and candidate.suffix.lower() == ".json":
        return candidate
    reports = sorted(
        config.runtime_root.glob("HOST_TRIPWIRE_CHECK_*.json"),
        key=lambda item: item.stat().st_mtime,
        reverse=True,
    )
    return reports[0] if reports else None


def summarize_tripwire_counter(summary: Dict[str, Any], primary: str, *fallbacks: str) -> int:
    for key in (primary,) + fallbacks:
        try:
            return int(summary.get(key) or 0)
        except (TypeError, ValueError):
            continue
    return 0


def lower_text(value: Any) -> str:
    return str(value or "").strip().lower()


def is_expected_operational_change(change: Dict[str, Any]) -> bool:
    classification = lower_text(change.get("Classification"))
    severity = lower_text(change.get("Severity"))
    return classification in ("expected", "expected_operational_change") or (classification == "info" and severity == "info")


def is_accepted_posture_change(change: Dict[str, Any]) -> bool:
    if bool(change.get("IsAcceptedDrift")):
        return True
    return lower_text(change.get("Classification")) == "accepted"


def is_guardrail_protected_change(change: Dict[str, Any]) -> bool:
    return bool(change.get("GuardrailMatched") or change.get("GuardrailProtected") or change.get("AcceptedDriftBlocked"))


def is_response_required_change(change: Dict[str, Any]) -> bool:
    classification = lower_text(change.get("Classification"))
    severity = lower_text(change.get("Severity"))
    if classification in ("critical", "warning", "response_required"):
        return True
    if severity in ("critical", "warning"):
        return True
    return is_guardrail_protected_change(change)


def is_needs_review_change(change: Dict[str, Any]) -> bool:
    if is_response_required_change(change):
        return False
    if is_accepted_posture_change(change) or is_expected_operational_change(change):
        return False
    classification = lower_text(change.get("Classification"))
    severity = lower_text(change.get("Severity"))
    return classification in ("review", "needs_review") or severity == "review"


def is_safe_acceptance_candidate(change: Dict[str, Any]) -> bool:
    if is_guardrail_protected_change(change) or is_accepted_posture_change(change) or is_expected_operational_change(change):
        return False
    section = lower_text(change.get("Section") or change.get("Category"))
    name = lower_text(change.get("ItemName") or change.get("Name"))
    path = lower_text(change.get("Path"))
    safe_markers = (
        "codex_monitor_ui.py",
        "codex_monitor_store.py",
        "invoke-host-tripwire.ps1",
        "tripwire-posture-baseline.ps1",
        "posture-drift-rules.json",
        "persona-profiles.json",
        "system-profiles.json",
        "protection-profiles.json",
        "codex-monitor.settings.json",
    )
    return section in ("appintegritybaseline", "appintegrity", "appfile", "configuration") and any(marker in name or marker in path for marker in safe_markers)


def compose_finding_title(change: Dict[str, Any]) -> str:
    return str(change.get("ItemName") or change.get("Name") or change.get("Title") or "Observed posture change")


def describe_finding_change(change: Dict[str, Any]) -> str:
    old_value = change.get("CurrentValue") if change.get("CurrentValue") not in (None, "") else change.get("OldValue")
    new_value = change.get("NewValue") if change.get("NewValue") not in (None, "") else change.get("BaselineValue")
    if old_value not in (None, "") and new_value not in (None, ""):
        return f"{old_value} -> {new_value}"
    if new_value not in (None, ""):
        return str(new_value)
    if old_value not in (None, ""):
        return str(old_value)
    change_type = str(change.get("ChangeType") or "").strip()
    if change_type:
        return change_type
    return "Details were not included in the latest report."


def explain_finding_importance(change: Dict[str, Any]) -> str:
    if change.get("AcceptedDriftBlockedReason"):
        return str(change.get("AcceptedDriftBlockedReason"))
    if is_guardrail_protected_change(change):
        return str(change.get("GuardrailReason") or "This finding cannot be accepted as routine because it affects a protected security condition.")
    if change.get("Interpretation"):
        return str(change.get("Interpretation"))
    if change.get("MatchedRuleDescription"):
        return str(change.get("MatchedRuleDescription"))
    if change.get("RecommendedAction"):
        return str(change.get("RecommendedAction"))
    if is_expected_operational_change(change):
        return "This matched a known normal OS or trusted application maintenance pattern and remains recorded for auditability."
    if is_accepted_posture_change(change):
        return "This exact change was previously reviewed and recorded locally. It remains in the audit trail."
    if is_needs_review_change(change):
        return "This change should be reviewed before deciding whether it needs mitigation or can be accepted later."
    return "Review the evidence to decide whether this change is expected, needs mitigation, or should remain open."


def finding_status_label(change: Dict[str, Any]) -> str:
    if is_accepted_posture_change(change):
        return "Accepted posture change"
    if is_expected_operational_change(change):
        return "Expected operational change"
    if is_guardrail_protected_change(change):
        return "Guardrail protected"
    if is_response_required_change(change):
        return "Response required"
    if is_needs_review_change(change):
        return "Needs review"
    return "Observed posture change"


def finding_tone(change: Dict[str, Any]) -> str:
    if is_guardrail_protected_change(change) or lower_text(change.get("Severity")) == "critical":
        return "high"
    if is_response_required_change(change) or is_needs_review_change(change):
        return "medium"
    if is_expected_operational_change(change) or is_accepted_posture_change(change):
        return "ok"
    return "info"


def finding_priority(change: Dict[str, Any]) -> tuple:
    title = compose_finding_title(change).lower()
    if is_guardrail_protected_change(change):
        return (0, title)
    if is_response_required_change(change):
        return (1, title)
    if is_needs_review_change(change):
        return (2, title)
    if is_accepted_posture_change(change):
        return (4, title)
    if is_expected_operational_change(change):
        return (5, title)
    return (3, title)


def mitigation_guidance(change: Dict[str, Any], persona_id: str) -> str:
    title = compose_finding_title(change).lower()
    reason = lower_text(change.get("GuardrailReason"))
    if "firewall" in title or "firewall" in reason:
        if persona_id == "tech":
            return "Review the evidence, then if the finding is confirmed use Windows Security or Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True. After changes, validate in Recover."
        return "Open Windows Security, go to Firewall & network protection, and turn Firewall on if the finding is confirmed. After that, use Recover to validate trusted operation."
    if "defender" in title or "defender" in reason:
        if persona_id == "tech":
            return "Review the evidence first. If the finding is confirmed, restore the affected Defender setting from Windows Security or Microsoft Defender management tools, then validate in Recover."
        return "Open Windows Security and restore the affected Microsoft Defender protection if the finding is confirmed. Then use Recover to validate trusted operation."
    return "Review the evidence before making changes. If you take action outside this app, use Recover afterward to confirm trusted operation."


def build_acceptance_helper_command(report_path: Path, finding_index: int) -> str:
    return (
        f'.\\accept-posture-drift.ps1 -ReportPath "{report_path}" '
        f'-FindingIndex {finding_index} -Reason "Reviewed expected change" '
        f'-StateDbPath ".\\state\\codex-monitor.db"'
    )


def build_sqlite_acceptance_helper_command(report_id: str, finding_id: str, state_db_path: Path) -> str:
    return (
        f'.\\accept-posture-drift.ps1 -ReportId "{report_id}" -FindingId "{finding_id}" '
        f'-Reason "Reviewed exact change" -StateDbPath "{state_db_path}"'
    )


def build_respond_finding(change: Dict[str, Any], index: int, report_path: Path) -> Dict[str, Any]:
    evidence = []
    for label, key in (
        ("Section", "Section"),
        ("Item type", "ItemType"),
        ("Field", "Field"),
        ("Path", "Path"),
        ("Command line", "CommandLine"),
        ("Baseline value", "BaselineValue"),
        ("Old value", "OldValue"),
        ("Current value", "CurrentValue"),
        ("New value", "NewValue"),
        ("Finding ID", "FindingId"),
        ("Report ID", "ReportId"),
    ):
        value = change.get(key)
        if value not in (None, ""):
            evidence.append({"label": label, "value": value})
    report_href = f"/report?path={urllib.parse.quote(str(report_path), safe='')}"
    classification = str(change.get("Classification") or "").strip() or "Unknown"
    severity = str(change.get("Severity") or "").strip() or "Unknown"
    return {
        "index": index,
        "title": compose_finding_title(change),
        "section": str(change.get("Section") or change.get("Category") or "Unknown"),
        "item_type": str(change.get("ItemType") or change.get("Category") or "Unknown"),
        "field": str(change.get("Field") or ""),
        "severity": severity,
        "classification": classification,
        "status_label": finding_status_label(change),
        "tone": finding_tone(change),
        "what_changed": describe_finding_change(change),
        "why_it_matters": explain_finding_importance(change),
        "recommended_response": str(change.get("RecommendedAction") or "Review the evidence and decide whether to investigate, mitigate, or leave the finding open."),
        "csf_mapping": str(change.get("CsfMapping") or "Not available"),
        "matched_rule_id": str(change.get("MatchedRuleId") or ""),
        "matched_rule_description": str(change.get("MatchedRuleDescription") or ""),
        "guardrail_matched": bool(change.get("GuardrailMatched") or change.get("GuardrailProtected")),
        "guardrail_reason": str(change.get("GuardrailReason") or ""),
        "is_accepted": is_accepted_posture_change(change),
        "accepted_reason": str(change.get("AcceptedDriftReason") or ""),
        "acceptance_id": str(change.get("AcceptanceId") or ""),
        "accepted_blocked": bool(change.get("AcceptedDriftBlocked")) or is_guardrail_protected_change(change),
        "accepted_blocked_reason": str(change.get("AcceptedDriftBlockedReason") or ""),
        "is_expected": is_expected_operational_change(change),
        "acceptance_allowed": is_safe_acceptance_candidate(change),
        "accept_helper_command": build_acceptance_helper_command(report_path, index),
        "report_path": str(report_path),
        "report_name": report_path.name,
        "report_href": report_href,
        "evidence": evidence,
        "source_change": change,
    }


def build_respond_queue_data(config: AppConfig, snapshot: Dict[str, Any]) -> Dict[str, Any]:
    persisted = [item for item in list_sqlite_reports_preview(config.state_db_path, limit=30) if item.get("report_type") == "tripwire_check"]
    if persisted:
        detail = get_sqlite_report_detail_preview(config.state_db_path, str(persisted[0].get("report_id") or ""))
        report = detail.get("report") or {}
        if detail.get("found") and report:
            report_id = str(report.get("report_id") or "")
            report_href = build_sqlite_report_href(report_id)
            export_path = Path(str(report.get("export_json_path") or config.runtime_root / report_id))
            active_findings, recorded_findings = [], []
            for index, stored in enumerate(detail.get("findings") or [], start=1):
                evidence = stored.get("evidence") or {}
                change = {"FindingId": stored.get("finding_id"), "Category": stored.get("category"), "Section": stored.get("category"), "Name": stored.get("title"), "ItemName": stored.get("title"), "ItemType": stored.get("category"), "Field": "CurrentValue", "CurrentValue": evidence.get("new_value", ""), "OldValue": evidence.get("old_value", ""), "BaselineValue": evidence.get("old_value", ""), "Severity": stored.get("severity"), "Classification": stored.get("classification"), "CsfMapping": stored.get("csf_mapping"), "MatchedRuleId": evidence.get("rule_id", ""), "MatchedRuleDescription": evidence.get("rule_description", ""), "GuardrailMatched": stored.get("guardrail_state") == "protected", "GuardrailReason": evidence.get("guardrail_reason", ""), "IsAcceptedDrift": stored.get("response_state") == "accepted", "RecommendedAction": stored.get("summary", "")}
                finding = build_respond_finding(change, index, export_path)
                finding["report_href"] = report_href
                finding["report_name"] = report_id
                finding["accept_helper_command"] = build_sqlite_acceptance_helper_command(report_id, str(stored.get("finding_id") or ""), config.state_db_path)
                if finding["is_accepted"] or finding["is_expected"]:
                    recorded_findings.append(finding)
                elif is_guardrail_protected_change(change) or is_response_required_change(change) or is_needs_review_change(change):
                    active_findings.append(finding)
            active_findings.sort(key=lambda item: finding_priority(item["source_change"]))
            recorded_findings.sort(key=lambda item: finding_priority(item["source_change"]))
            observed = len(active_findings) + len(recorded_findings)
            guardrails = sum(1 for item in active_findings if item.get("guardrail_matched"))
            accepted = sum(1 for item in recorded_findings if item.get("is_accepted"))
            return {"queue_state": "active" if active_findings else ("recorded_only" if observed else "no_drift"), "queue_message": f"{len(active_findings)} finding(s) need a decision or response." if active_findings else "No findings currently require response.", "latest_report_path": str(export_path), "latest_report_href": report_href, "latest_report_name": report_id, "latest_report_time": report.get("collection_time") or "", "active_findings": active_findings, "recorded_findings": recorded_findings, "summary_cards": [{"label": "Response required", "value": len(active_findings), "tone": "high" if active_findings else "ok"}, {"label": "Guardrail protected", "value": guardrails, "tone": "high" if guardrails else "ok"}, {"label": "Accepted posture changes", "value": accepted, "tone": "ok"}, {"label": "Observed posture changes", "value": observed, "tone": "info"}], "observed_count": observed}

    base = {
        "queue_state": "missing_report",
        "queue_message": "No posture check report is available yet. Run a posture check from Detect.",
        "latest_report_path": "",
        "latest_report_href": "/detect",
        "latest_report_name": "",
        "latest_report_time": "",
        "active_findings": [],
        "recorded_findings": [],
        "summary_cards": [],
        "observed_count": 0,
    }
    # Phase 5: reports are operationally sourced only from SQLite.  Legacy
    # JSON parsing remains below solely as retained migration-reference code.
    return base

    report_path = find_latest_tripwire_check_report(config, snapshot)
    if not report_path:
        return base
    try:
        payload = parse_json(report_path)
    except Exception as exc:
        base.update({
            "queue_state": "report_error",
            "queue_message": f"Latest posture report could not be parsed: {exc}",
            "latest_report_path": str(report_path),
            "latest_report_href": f"/report?path={urllib.parse.quote(str(report_path), safe='')}",
            "latest_report_name": report_path.name,
        })
        return base

    summary = payload.get("Summary") or {}
    metadata = payload.get("Metadata") or {}
    changes = payload.get("Changes") or []
    if not isinstance(changes, list):
        changes = []

    active_findings = []
    recorded_findings = []
    for index, change in enumerate(changes, start=1):
        if not isinstance(change, dict):
            continue
        finding = build_respond_finding(change, index, report_path)
        if finding["is_accepted"] or finding["is_expected"]:
            recorded_findings.append(finding)
        elif is_guardrail_protected_change(change) or is_response_required_change(change) or is_needs_review_change(change):
            active_findings.append(finding)

    active_findings.sort(key=lambda item: finding_priority(item["source_change"]))
    recorded_findings.sort(key=lambda item: finding_priority(item["source_change"]))

    response_required = summarize_tripwire_counter(summary, "response_required_count", "warning_drift_count", "critical_drift_count")
    needs_review = summarize_tripwire_counter(summary, "posture_review_count", "review_drift_count")
    guardrail_protected = summarize_tripwire_counter(summary, "guardrail_protected_count", "guardrail_matched_count")
    accepted = summarize_tripwire_counter(summary, "accepted_posture_change_count", "accepted_drift_count")
    expected = summarize_tripwire_counter(summary, "expected_operational_change_count", "expected_churn_count")
    observed = summarize_tripwire_counter(summary, "observed_posture_change_count", "unexpected_drift_count")
    if observed == 0:
        observed = len(active_findings) + len(recorded_findings)

    summary_cards = [
        {"label": "Response required", "value": response_required, "tone": "high" if response_required else "ok"},
        {"label": "Needs review", "value": needs_review, "tone": "medium" if needs_review else "ok"},
        {"label": "Guardrail protected", "value": guardrail_protected, "tone": "high" if guardrail_protected else "ok"},
        {"label": "Accepted posture changes", "value": accepted, "tone": "ok"},
        {"label": "Expected operational changes", "value": expected, "tone": "ok"},
        {"label": "Observed posture changes", "value": observed, "tone": "info"},
    ]

    queue_message = "No findings currently require response. Observed changes may be expected operational changes or accepted posture changes."
    queue_state = "recorded_only"
    if observed == 0:
        queue_state = "no_drift"
        queue_message = "No configuration drift was detected in the latest posture check."
    elif active_findings:
        queue_state = "active"
        queue_message = f"{len(active_findings)} finding(s) need a decision or response."

    return {
        "queue_state": queue_state,
        "queue_message": queue_message,
        "latest_report_path": str(report_path),
        "latest_report_href": f"/report?path={urllib.parse.quote(str(report_path), safe='')}",
        "latest_report_name": report_path.name,
        "latest_report_time": metadata.get("CollectionTimeUtc") or report_path.stat().st_mtime,
        "active_findings": active_findings,
        "recorded_findings": recorded_findings,
        "summary_cards": summary_cards,
        "observed_count": observed,
    }


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
    alert_id = str(alert.get("alert_id") or "")
    report_id = str(alert.get("report_id") or "")
    report_href = build_sqlite_report_href(report_id) if report_id else "/reports"
    anchor = re.sub(r"[^a-z0-9]+", "-", alert_id.lower()).strip("-") or "alert"
    mark_expected_detail = "Mark expected is a planning-only step in this UI. Document expected changes outside the app until alert workflow state is implemented."
    return (
        '<div class="task-actions" style="margin-top:8px">'
        f'<a class="btn" href="#alert-{esc(anchor)}-ack">Acknowledge</a>'
        f'<a class="btn" href="#alert-{esc(anchor)}-investigate">Investigate</a>'
        f'<a class="btn" href="{esc(report_href)}">View evidence</a>'
        f'<a class="btn" href="#alert-{esc(anchor)}-export">Export alert</a>'
        f'<a class="btn" href="#alert-{esc(anchor)}-expected">Mark expected</a>'
        '</div>'
        f'<details class="inline-detail mini" id="alert-{esc(anchor)}-ack"><summary>Acknowledge</summary><div class="detail-body">Lifecycle state is currently {esc(lifecycle_state)}. Use this step to note that the alert has been seen and is awaiting human review. No backend state is changed yet.</div></details>'
        f'<details class="inline-detail mini" id="alert-{esc(anchor)}-investigate"><summary>Investigate</summary><div class="detail-body">Open the alert evidence, review the related report, and compare the alert against recent expected maintenance or software changes on this PC.</div></details>'
        f'<details class="inline-detail mini" id="alert-{esc(anchor)}-expected"><summary>Mark expected</summary><div class="detail-body">{esc(mark_expected_detail)}</div></details>'
        f'<details class="inline-detail mini" id="alert-{esc(anchor)}-export"><summary>Export alert</summary><div class="detail-body">Use `codex_monitor_store.py export-alert --alert-id {esc(alert_id)}` with an operator-selected output path.</div></details>'
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
            ((status.get("LatestArtifacts") or {}).get(key) or {}).get("LastWriteTimeUtc"),
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
  <td><a data-record-modal href="/alert?id={urllib.parse.quote(str(alert.get("alert_id") or ""), safe="")}">{esc(alert.get("summary") or alert.get("alert_id"))}</a>{message_markup}{action_markup}</td>
  <td>{lifecycle_markup}</td>
  <td>{esc(alert.get("finding_id") or "—")}</td>
  <td>{esc(pretty_time(alert.get("created_at") or "—"))}</td>
</tr>
"""


def render_report_row(report: Dict[str, Any]) -> str:
    encoded = urllib.parse.quote(report.get("path", ""), safe="")
    href = build_sqlite_report_href(str(report.get("report_id"))) if report.get("report_id") else f"/report?path={encoded}"
    summary_parts = [f"{key}={value}" for key, value in report.get("summary", {}).items() if value not in (None, "", 0)]
    summary_text = ", ".join(summary_parts) if summary_parts else "No summary fields"
    summary_markup = compact_detail("View summary", summary_text) if len(summary_text) > 90 else esc(summary_text)
    return f"""
<tr>
  <td><a data-record-modal href="{esc(href)}">{esc(report.get("name") or report.get("report_id"))}</a></td>
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
    sqlite_alerts = list_sqlite_alerts(config.state_db_path)
    pending_alerts = [alert for alert in sqlite_alerts if str(alert.get("lifecycle_state") or "").lower() == "pending"]
    archive_alerts = [alert for alert in sqlite_alerts if str(alert.get("lifecycle_state") or "").lower() != "pending"]
    recent_reports = list_sqlite_reports_preview(config.state_db_path)
    return {
        "ui_snapshot_collected_at": datetime.now(timezone.utc).isoformat(),
        "status": status,
        "task_details": task_details,
        "indicators": indicators,
        "pending_alerts": pending_alerts,
        "archive_alerts": archive_alerts,
        "recent_reports": recent_reports,
    }


def refresh_sqlite_backed_snapshot(config: AppConfig, snapshot: Dict[str, Any]) -> Dict[str, Any]:
    """Refresh data that scheduled collectors persist without rerunning Windows inventory."""
    refreshed = copy.deepcopy(snapshot)
    refreshed["indicators"] = query_indicator_stats(config.state_db_path)
    sqlite_alerts = list_sqlite_alerts(config.state_db_path)
    refreshed["pending_alerts"] = [alert for alert in sqlite_alerts if str(alert.get("lifecycle_state") or "").lower() == "pending"]
    refreshed["archive_alerts"] = [alert for alert in sqlite_alerts if str(alert.get("lifecycle_state") or "").lower() != "pending"]
    refreshed["recent_reports"] = list_sqlite_reports_preview(config.state_db_path)
    return refreshed


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
    respond_queue = build_respond_queue_data(config, snapshot)
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
    respond_summary = respond_queue["queue_message"] if respond_queue.get("queue_message") else (
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
            "ui_persona": CSF_ANALYST_PERSONA_ID,
            "persona_profile": effective_persona,
            "available_personas": [effective_persona],
            "system_profile": effective_system_profile,
            "profile_catalog_paths": {key: str(value) for key, value in profile_catalog_paths(config.repo_root).items()},
            "csf_profile_context": snapshot.get("csf_profile_context") or {"active_profile": {}, "defined_profiles": []},
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
                {"label": "Latest IOC report", "value": pretty_time(((status.get("LatestArtifacts") or {}).get("LatestIocReport") or {}).get("LastWriteTimeUtc") or "Missing")},
                {"label": "Latest Tripwire report", "value": pretty_time(((status.get("LatestArtifacts") or {}).get("LatestTripwireReport") or {}).get("LastWriteTimeUtc") or "Missing")},
                {"label": "Latest RSS report", "value": pretty_time(((status.get("LatestArtifacts") or {}).get("LatestThreatRssReport") or {}).get("LastWriteTimeUtc") or "Missing")},
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
                "queue_state": respond_queue.get("queue_state"),
                "queue_message": respond_queue.get("queue_message"),
                "active_findings": respond_queue.get("active_findings") or [],
                "recorded_findings": respond_queue.get("recorded_findings") or [],
                "summary_cards": respond_queue.get("summary_cards") or [],
                "latest_report_path": respond_queue.get("latest_report_path") or "",
                "latest_report_href": respond_queue.get("latest_report_href") or "/detect",
                "latest_report_name": respond_queue.get("latest_report_name") or "",
                "latest_report_time": respond_queue.get("latest_report_time") or "",
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
    model["csf_explorer_selection"] = dict(snapshot.get("csf_explorer_selection") or {})
    model["csf_subcategory_guidance"] = dict(snapshot.get("csf_subcategory_guidance") or {})
    model["csf_subcategory_profile_metadata"] = dict(snapshot.get("csf_subcategory_profile_metadata") or {})
    model["csf_subcategory_product_examples"] = dict(snapshot.get("csf_subcategory_product_examples") or {})
    model["csf_profile_assessments"] = dict(snapshot.get("csf_profile_assessments") or {})
    model["csf_profile_scope"] = dict(snapshot.get("csf_profile_scope") or {})
    model["csf_community_profile_guidance"] = dict(snapshot.get("csf_community_profile_guidance") or {})
    model["csf_current_assessments"] = dict(snapshot.get("csf_current_assessments") or {})
    # Keep Tile 3's per-request SQLite records and diagnostic path available to
    # the CSF renderer; this model is otherwise deliberately selective.
    model["csf_outcome_records"] = dict(snapshot.get("csf_outcome_records") or {})
    model["csf_information_flow"] = dict(snapshot.get("csf_information_flow") or {})
    model["csf_state_db_path"] = str(snapshot.get("csf_state_db_path") or "")
    return model


FUNCTION_ROUTE_ORDER = [
    ("govern", "/govern", "Govern"),
    ("identify", "/identify", "Identify"),
    ("protect", "/protect", "Protect"),
    ("detect", "/detect", "Detect"),
    ("respond", "/respond", "Respond"),
    ("recover", "/recover", "Recover"),
]

CSF_FUNCTION_ID_BY_ROUTE = {
    "/govern": "GV",
    "/identify": "ID",
    "/protect": "PR",
    "/detect": "DE",
    "/respond": "RS",
    "/recover": "RC",
}




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


CSF_FUNCTION_GUIDANCE = {
    "govern": ("Set direction and accountability.", "Use this space for policy, approval authority, and evidence needed to authorize risk decisions.", "Move to Identify when you need to assess a risk or exception."),
    "identify": ("Understand assets, risk, and gaps.", "Use this space to assess a finding's impact and record the risk decision it requires.", "Move to Protect to review configuration controls and baselines."),
    "protect": ("Maintain safeguards and trusted configuration.", "Use this space for configuration-baseline reviews, control health, and authorized changes.", "Move to Detect when you need evidence of a change or possible threat."),
    "detect": ("Find and analyze possible adverse events.", "Use this space for observed changes, IOC matches, and evidence that needs classification.", "Move to Respond only when investigation indicates a possible security incident."),
    "respond": ("Investigate and manage credible security events.", "Use this space to scope, document, and mitigate findings that require a response.", "Move to Recover after corrective actions need validation."),
    "recover": ("Restore and improve trusted operation.", "Use this space to validate recovery, retain lessons learned, and return safeguards to a trusted state.", "Move to Govern to improve policy and approval rules from what was learned."),
}


def csf_section_for_path(current_path: str) -> str:
    return str(current_path or "/").strip("/").split("/", 1)[0].lower()


def render_primary_nav(current_path: str, *, persona_profile: Dict[str, Any], show_technical: bool = False) -> str:
    actions = []
    for key, href, label in FUNCTION_ROUTE_ORDER:
        is_active = current_path == href
        active = " active" if is_active else ""
        current = ' aria-current="page"' if is_active else ""
        purpose, use_here, _next_step = CSF_FUNCTION_GUIDANCE[key]
        actions.append(
            f'<a class="csf-action csf-function-{esc(key)}{active}" data-csf-route href="{href}"{current}'
            f' data-csf-purpose="{esc(purpose)}" data-csf-use="{esc(use_here)}">'
            f'<span>{esc(label)}</span></a>'
        )
    return "".join(actions)


def csf_guidance_values(current_path: str) -> tuple[str, str]:
    section = csf_section_for_path(current_path)
    if section not in CSF_FUNCTION_GUIDANCE:
        return (
            "CSF Analyst overview.",
            "Choose a CSF Function to understand its purpose, inspect evidence, and take the next appropriate action.",
        )
    purpose, use_here, _next_step = CSF_FUNCTION_GUIDANCE[section]
    return purpose, use_here


def build_csf_explorer_href(current_path: str, category_id: str = "", subcategory_id: str = "") -> str:
    query: Dict[str, str] = {}
    if category_id:
        query["csf_category"] = category_id
    if subcategory_id:
        query["csf_subcategory"] = subcategory_id
    return current_path + (("?" + urllib.parse.urlencode(query)) if query else "")


def render_de_cm_monitoring_mapping(model: Dict[str, Any]) -> str:
    """Render the reviewed, category-level DE.CM task mapping and nothing else."""
    task_names = (model.get("task_job_health") or {}).get("groups", {}).get("detect", [])
    tasks_by_name = (model.get("task_job_health") or {}).get("by_name", {})
    task_rows = []
    for task_name in task_names:
        task = tasks_by_name.get(task_name)
        if not task:
            continue
        state = classify_task_result(task)
        task_rows.append(
            f'''<div class="csf-outcome-state"><div class="task-head"><div><strong>{esc(task_name)}</strong>
<div class="mini">Last run: {esc(pretty_time(task.get("LastRunTime") or ""))} · Next run: {esc(pretty_time(task.get("NextRunTime") or ""))}</div>
<div class="mini">{esc(state["message"])} This task contributes monitored local evidence for this PC.</div></div>
<div class="task-actions"><span>{render_status_badge(state["label"], state["tone"])} </span><form method="post" action="/run-task"><input type="hidden" name="task_name" value="{esc(task_name)}"><input type="hidden" name="return_to" value="/detect"><button class="btn primary" type="submit">Run now</button></form></div></div></div>'''
        )
    if not task_rows:
        return '<div class="csf-outcome-state"><h3>Local evidence and actions</h3><p>No reviewed monitoring-task records are available in the current snapshot. This is an unavailable-evidence state, not a passing result.</p></div>'
    return f'''<section class="csf-outcome" aria-labelledby="de-cm-mapping-title">
  <div class="kicker">Reviewed product mapping</div>
  <div id="de-cm-mapping-title" class="focus-title">DE.CM · Continuous Monitoring</div>
  <p>These scheduled collectors keep locally available threat intelligence and host-change evidence current. Their status indicates monitoring coverage, not that the PC is free of threats.</p>
  <h3>Monitoring task history and reviewed actions</h3>{"".join(task_rows)}
</section>'''


def render_nist_implementation_examples(subcategory: Dict[str, Any]) -> str:
    """Render every official NIST example in the compact learning tile."""
    examples = [str(example).strip() for example in subcategory.get("implementation_examples") or [] if str(example).strip()]
    if not examples:
        return (
            '<div class="csf-outcome-state"><p>No NIST implementation example is available in the vendored catalog for this outcome.</p></div>'
        )
    if len(examples) == 1:
        return f'<div class="csf-outcome-state"><p>{esc(examples[0])}</p></div>'
    rows = "".join(f"<li>{esc(example)}</li>" for example in examples)
    return f'<div class="csf-outcome-state"><ul>{rows}</ul></div>'


def render_csf_assessment_prototype(
    metadata: Dict[str, Any],
    plain_english_text: str = "",
    examples: Optional[List[str]] = None,
    profile_assessment: Optional[Dict[str, Any]] = None,
    current_assessment: Optional[Dict[str, Any]] = None,
    subcategory_id: str = "",
    category_id: str = "",
    return_to: str = "",
    reviewed_actions: Optional[List[Dict[str, Any]]] = None,
    supporting_basis: Optional[List[Dict[str, Any]]] = None,
    record_read_error: str = "",
    reviewed_action_total: int = 0,
    information_flow: Optional[Dict[str, List[Dict[str, Any]]]] = None,
    allow_record_creation: bool = True,
) -> str:
    """Render a non-persistent preview of the method-specific assessment workspace."""
    method = str(metadata.get("assessment_method") or "").strip().lower()
    guidance = str(metadata.get("research_guidance") or "").strip()
    plain_text = str(plain_english_text or "").strip()
    note_required = bool(metadata.get("supporting_note_required"))
    profile_level = str((profile_assessment or {}).get("target_assessment_level") or "").strip().lower()
    target_reason = str(
        (profile_assessment or {}).get("profile_outcome_reason")
        or (profile_assessment or {}).get("target_reason")
        or ""
    ).strip()
    proposed_priority = proposed_priority_label((profile_assessment or {}).get("community_priority"))
    current_level = str((current_assessment or {}).get("assessment_level") or "").strip().lower()
    option_labels = {
        "fully_implemented": "Fully implemented",
        "partly_implemented": "Partly implemented",
        "not_implemented": "Not implemented",
        "not_applicable": "Not applicable",
    }
    current_options = "".join(
        f'<button class="csf-assessment-choice{(" active" if current_level == value else "")}" type="submit" name="assessment_level" value="{value}">{label}</button>'
        for value, label in option_labels.items()
    )
    profile_options = "".join(
        f'<button class="csf-assessment-choice{(" active" if profile_level == value else "")}" type="button" disabled>{label}</button>'
        for value, label in option_labels.items()
    )
    current_status = (
        f'Current assessment: {option_labels[current_level]}.'
        if current_level in option_labels
        else "No current assessment is recorded."
    )
    target_note = target_reason or (f"NIST proposed priority: {proposed_priority}" if proposed_priority else "No reason is recorded for this Target.")
    response = f'''<div class="csf-assessment-comparison"><div class="csf-assessment-block"><div class="csf-assessment-inline"><strong>Target</strong><div class="csf-response-options csf-profile-assessment">{profile_options}</div></div><p>{esc(target_note)}</p></div><div class="csf-assessment-block"><div class="csf-assessment-inline"><strong>Current</strong><form method="post" action="/set-csf-current-assessment"><input type="hidden" name="subcategory_id" value="{esc(subcategory_id)}"><input type="hidden" name="category_id" value="{esc(category_id)}"><input type="hidden" name="return_to" value="{esc(return_to)}"><div class="csf-response-options">{current_options}</div></form></div><p>{esc(current_status)}</p></div></div>'''
    query = urllib.parse.urlencode({"csf_category": category_id, "csf_subcategory": subcategory_id, "return_to": return_to})
    action_rows = "".join(
        f'<a class="csf-record-row" data-record-modal href="/csf-reviewed-action?{query}&amp;action_id={urllib.parse.quote(str(row.get("action_id") or ""), safe="")}"><strong>{esc(row.get("title") or "Untitled action")}</strong><span>{esc((str(row.get("control_id") or "").strip() or "Manual action") + " · " + str(row.get("action_status") or "").replace("_", " ").title())}</span></a>'
        for row in (reviewed_actions or [])
    ) or f'<p class="csf-record-empty">{esc("Unable to load records: " + record_read_error) if record_read_error else "No action is recorded yet."}</p>'
    basis_rows = "".join(
        f'<a class="csf-record-row" data-record-modal href="/csf-supporting-basis?{query}&amp;basis_id={urllib.parse.quote(str(row.get("basis_id") or ""), safe="")}"><strong>{esc(row.get("title") or "Untitled evidence")}</strong><span>{esc(str(row.get("basis_type") or "").replace("_", " ").title())}</span></a>'
        for row in (supporting_basis or [])
    ) or f'<p class="csf-record-empty">{esc("Unable to load records: " + record_read_error) if record_read_error else "No supporting basis is recorded yet."}</p>'
    record_read_only_note = '<span class="mini">Frozen Profile — read-only</span>'
    add_action_control = f'<a class="csf-add-record" data-record-modal aria-label="Add action" href="/csf-reviewed-action?{query}">+</a>' if allow_record_creation else record_read_only_note
    actions = f'<div class="csf-assessment-block"><div class="csf-record-list-head"><strong>Actions</strong>{add_action_control}</div><div class="csf-record-list" tabindex="0" aria-label="Actions">{action_rows}</div></div>'
    if method == "evidence":
        body = '''<div class="csf-assessment-block"><strong>Local evidence</strong><p>No reviewed local-evidence mapping is available yet. This is not a passing result.</p></div>''' + response
    elif method == "attestation":
        body = '''<div class="csf-assessment-block"><strong>Confirmation</strong><p>Ask the person responsible for this PC to confirm the outcome and its basis.</p></div>''' + response
    elif method == "review":
        body = response
    elif method == "hybrid":
        body = '''<div class="csf-assessment-block"><strong>Local evidence</strong><p>No reviewed local-evidence mapping is available yet. This is not a passing result.</p></div><div class="csf-assessment-block"><strong>Human confirmation</strong><p>Confirm the context and outcome with the person responsible for this PC.</p></div>''' + response
    else:
        body = '<div class="csf-assessment-block"><p>Assessment metadata is not available for this outcome.</p></div>'
    add_evidence_control = f'<a class="csf-add-record" data-record-modal aria-label="Add evidence" href="/csf-supporting-basis?{query}">+</a>' if allow_record_creation else record_read_only_note
    supporting_basis = f'<div class="csf-assessment-block"><div class="csf-record-list-head"><strong>Evidence</strong>{add_evidence_control}</div><div class="csf-record-list" tabindex="0" aria-label="Evidence">{basis_rows}</div></div>'
    example_values = [str(example).strip() for example in (examples or []) if str(example).strip()]
    if len(example_values) == 1:
        example_content = f'<p class="mini">{esc(example_values[0])}</p>'
    elif example_values:
        example_content = '<ul class="mini">' + ''.join(f'<li>{esc(example)}</li>' for example in example_values) + '</ul>'
    else:
        example_content = '<p class="mini">No local example is mapped for this outcome yet.</p>'
    flow = information_flow or {"inputs": [], "outputs": []}
    flow_inputs = list(flow.get("inputs") or [])
    flow_outputs = list(flow.get("outputs") or [])
    selected_catalog_record = csf_catalog.find_official_subcategory(subcategory_id) or {}
    selected_short_description = str(selected_catalog_record.get("short_description") or "").strip()
    selected_label = f'{subcategory_id}: {selected_short_description}' if selected_short_description else subcategory_id

    def flow_label(flow_subcategory_id: str) -> str:
        record = csf_catalog.find_official_subcategory(flow_subcategory_id) or {}
        short_description = str(record.get("short_description") or "").strip()
        return f'{flow_subcategory_id}: {short_description}' if short_description else flow_subcategory_id

    def dependency_label(kind: str) -> str:
        return {"required_input": "required input", "planning_input": "planning input", "event_input": "event input"}.get(kind, kind.replace("_", " "))

    output_graphs = "".join(
        f'''<div class="csf-flow-graph">
  <div class="csf-flow-node source"><strong>{esc(selected_label)}</strong><span>This outcome</span></div>
  <div class="csf-flow-arrow"><span>produces</span><b>→</b></div>
  <div class="csf-flow-node information"><strong>{esc(str(item.get("title") or "Information"))}</strong><span>{esc(str(item.get("description") or ""))}</span></div>
  <div class="csf-flow-arrow"><span>used by</span><b>→</b></div>
  <div class="csf-flow-consumers">{''.join(f'<div class="csf-flow-consumer"><strong>{esc(flow_label(str(use.get("subcategory_id") or "")))}</strong><span>{esc(dependency_label(str(use.get("dependency_kind") or "")))}</span><p>{esc(str(use.get("reason") or ""))}</p></div>' for use in item.get("uses") or []) or '<p class="csf-record-empty">No direct downstream use is defined yet.</p>'}</div>
</div>'''
        for item in flow_outputs
    )
    input_graphs = "".join(
        f'''<div class="csf-flow-graph input">
  <div class="csf-flow-consumers">{''.join(f'<div class="csf-flow-consumer"><strong>{esc(flow_label(str(source.get("subcategory_id") or "")))}</strong><p>{esc(str(source.get("guidance") or ""))}</p></div>' for source in item.get("sources") or []) or '<p class="csf-record-empty">A source outcome has not been defined yet.</p>'}</div>
  <div class="csf-flow-arrow"><span>produces</span><b>→</b></div>
  <div class="csf-flow-node information"><strong>{esc(str(item.get("title") or "Information"))}</strong><span>{esc(str(item.get("description") or ""))}</span></div>
  <div class="csf-flow-arrow"><span>used here</span><b>→</b></div>
  <div class="csf-flow-node source"><strong>{esc(selected_label)}</strong><span>{esc(dependency_label(str(item.get("dependency_kind") or "")))}</span></div>
</div>'''
        for item in flow_inputs
    )
    if flow_outputs or flow_inputs:
        if flow_outputs:
            first_output = flow_outputs[0]
            consumer_labels = [str(item.get("subcategory_id") or "") for item in first_output.get("uses") or []]
            downstream_text = ", ".join(consumer_labels[:3]) + (" and other outcomes" if len(consumer_labels) > 3 else "")
            why_text = f'This outcome records {str(first_output.get("title") or "information").lower()}. That information is used by {downstream_text or "later CSF outcomes"}.'
        else:
            first_input = flow_inputs[0]
            # The relationship catalog carries a purpose-written explanation of
            # how an incoming information item is used at this outcome.  Do not
            # reduce that to a generic prerequisite sentence: it makes the
            # outcome sound like a gate rather than explaining its purpose.
            why_text = str(first_input.get("use_reason") or "").strip()
            if not why_text:
                why_text = (
                    f'This outcome applies {str(first_input.get("title") or "relevant information").lower()} '
                    'when carrying out its stated outcome.'
                )
        if flow_outputs and flow_inputs:
            flow_buttons = '<button class="csf-information-flow-button" type="button" data-information-flow-modal aria-haspopup="dialog">Information flow</button>'
        elif flow_outputs:
            flow_buttons = '<button class="csf-information-flow-button" type="button" data-information-flow-modal data-information-flow-direction="downstream" aria-haspopup="dialog">Information flow</button>'
        else:
            flow_buttons = '<button class="csf-information-flow-button" type="button" data-information-flow-modal data-information-flow-direction="upstream" aria-haspopup="dialog">Information flow</button>'
        flow_context = f'''<div class="csf-why-matters"><div><div class="kicker">Why this matters</div><p>{esc(why_text)}</p></div><div class="csf-information-flow-buttons">{flow_buttons}</div></div>
<template id="csf-information-flow-template"><div class="modal-backdrop"><section class="modal-dialog csf-information-flow-dialog" role="dialog" aria-modal="true" aria-labelledby="csf-information-flow-title"><header class="modal-head"><div><div class="kicker">Why this outcome is necessary</div><h2 id="csf-information-flow-title">Information flow</h2><p class="csf-modal-outcome">{esc(selected_label)}</p></div><button class="btn" type="button" data-modal-close>Close</button></header><div class="modal-body csf-information-flow-body">{f'<section data-information-flow-section="downstream"><h3>Information this outcome provides</h3>{output_graphs}</section>' if output_graphs else ''}{f'<section data-information-flow-section="upstream"><h3>Information this outcome needs</h3>{input_graphs}</section>' if input_graphs else ''}</div></section></div></template>'''
    else:
        flow_context = ""
    return f'''<div class="csf-assessment-prototype">
  <div class="csf-assessment-context"><p class="mini">{esc(plain_text or guidance or "Product explanation is not available for this outcome.")}</p>{example_content}{flow_context}</div>
  {body}<div class="csf-assessment-comparison">{actions}{supporting_basis}</div>
</div>'''


def render_csf_explorer(
    current_path: str,
    selection: Optional[Dict[str, str]] = None,
    model: Optional[Dict[str, Any]] = None,
) -> str:
    """Render the selected Function as separate Category, Subcategory, outcome, and evidence tiles."""
    function_id = CSF_FUNCTION_ID_BY_ROUTE.get(current_path)
    if not function_id:
        return ""
    catalog = csf_catalog.load_official_catalog()
    function = next((item for item in catalog["functions"] if item["id"] == function_id), None)
    if function is None:
        return ""

    profile_scope = dict((model or {}).get("csf_profile_scope") or {})
    selected_statuses = {"included", "inherited"}
    visible_categories = []
    for category in function["categories"]:
        visible_subcategories = [
            subcategory for subcategory in category["subcategories"]
            if profile_scope.get(str(subcategory["id"]), "included") in selected_statuses
        ]
        if profile_scope.get(str(category["id"]), "included") in selected_statuses and visible_subcategories:
            visible_categories.append({**category, "subcategories": visible_subcategories})

    selection = selection or {}
    selected_category_id = str(selection.get("category_id") or "").strip().upper()
    selected_category = next((item for item in visible_categories if item["id"] == selected_category_id), None)
    selected_subcategory_id = str(selection.get("subcategory_id") or "").strip().upper()
    selected_subcategory = None
    assessment_heading = "Evidence and actions"
    if selected_category is not None:
        selected_subcategory = next(
            (item for item in selected_category["subcategories"] if item["id"] == selected_subcategory_id),
            None,
        )

    category_rows = "".join(
        f'<a class="csf-explorer-row{(" active" if category is selected_category else "")}" data-csf-route '
        f'href="{esc(build_csf_explorer_href(current_path, category["id"]))}">'
        f'<span class="csf-explorer-id">{esc(category["id"])}</span>'
        f'<span class="csf-explorer-title">{esc(category["title"])}</span>'
        f'<span class="csf-explorer-copy">{esc(category["outcome"] or "Official NIST CSF Category.")}</span></a>'
        for category in visible_categories
    )
    if selected_category is None:
        subcategory_heading = "Select a Category · Subcategories"
        subcategory_content = '<div class="csf-explorer-placeholder">Select a Category to open its official Subcategories and outcomes.</div>'
        outcome_content = '<div class="csf-explorer-placeholder">Select a Category, then a Subcategory, to see what it means for this PC.</div>'
        evidence_content = '<div class="csf-explorer-placeholder">Select a Subcategory to see the evidence and actions reviewed for that outcome.</div>'
    else:
        subcategory_heading = f'{selected_category["id"]} · {selected_category["title"]} · Subcategories'
        subcategory_content = "".join(
            f'<a class="csf-explorer-row{(" active" if subcategory is selected_subcategory else "")}" data-csf-route '
            f'href="{esc(build_csf_explorer_href(current_path, selected_category["id"], subcategory["id"]))}">'
            f'<span class="csf-explorer-id">{esc(subcategory["id"])}</span>'
            f'<span class="csf-explorer-title">{esc(subcategory["title"])}</span>'
            f'<span class="csf-explorer-copy">{esc(subcategory["outcome"] or "Official NIST CSF Subcategory.")}</span></a>'
            for subcategory in selected_category["subcategories"]
        )
        if selected_subcategory is None:
            outcome_content = f'''<div class="csf-outcome">
  <div class="kicker">Official NIST CSF 2.0 Category</div>
  <div class="focus-label">{esc(selected_category["id"])} · {esc(selected_category["title"])}</div>
  <div class="focus-title">{esc(selected_category["outcome"] or "Official Category outcome text is not available in the catalog source.")}</div>
  <p>Select a Subcategory to inspect its specific outcome and local evidence mapping.</p>
</div>'''
            evidence_content = (
                render_de_cm_monitoring_mapping(model or {})
                if current_path == "/detect" and selected_category["id"] == "DE.CM"
                else '<div class="csf-explorer-placeholder">No reviewed Category-level evidence or action is mapped here. Select a Subcategory for its outcome-specific mapping.</div>'
            )
            outcome_content = '<div class="csf-explorer-placeholder">Select a Subcategory to see what it means for this PC.</div>'
        else:
            outcome_content = f'''<section class="csf-outcome" aria-labelledby="csf-outcome-title">
  <div class="kicker">Official NIST CSF 2.0 outcome</div>
  <div class="focus-label">{esc(selected_subcategory["id"])} · {esc(selected_subcategory["title"])}</div>
  <div id="csf-outcome-title" class="focus-title">{esc(selected_subcategory["outcome"] or "Official outcome text is not available in the catalog source.")}</div>
</section>'''
            community_guidance = dict(((model or {}).get("csf_community_profile_guidance") or {}).get(selected_subcategory["id"]) or {})
            if str(community_guidance.get("note") or "").strip():
                source = str(community_guidance.get("source") or "").strip()
                source_html = f'<p class="mini">{esc(source)}</p>' if source else ""
                outcome_content = f'<div class="csf-outcome-state"><p>{esc(str(community_guidance.get("note") or ""))}</p>{source_html}</div>'
            else:
                outcome_content = render_nist_implementation_examples(selected_subcategory)
            metadata = dict(((model or {}).get("csf_subcategory_profile_metadata") or {}).get(selected_subcategory["id"]) or {})
            metadata["sqlite_path"] = str((model or {}).get("csf_state_db_path") or "")
            assessment_method = str(metadata.get("assessment_method") or "").strip().lower()
            if assessment_method in {"evidence", "attestation", "review", "hybrid"}:
                assessment_heading = assessment_method.title()
            plain_english_text = str(((model or {}).get("csf_subcategory_guidance") or {}).get(selected_subcategory["id"]) or "").strip()
            product_record = dict(((model or {}).get("csf_subcategory_product_examples") or {}).get(selected_subcategory["id"]) or {})
            product_examples = [str(item).strip() for item in (product_record.get("examples") or []) if str(item).strip()]
            profile_assessment = dict(((model or {}).get("csf_profile_assessments") or {}).get(selected_subcategory["id"]) or {})
            current_assessment = dict(((model or {}).get("csf_current_assessments") or {}).get(selected_subcategory["id"]) or {})
            active_profile = dict(((model or {}).get("app") or {}).get("csf_profile_context", {}).get("active_profile") or {})
            evidence_content = render_csf_assessment_prototype(
                metadata,
                plain_english_text,
                product_examples,
                profile_assessment,
                current_assessment,
                selected_subcategory["id"],
                selected_category["id"],
                current_path,
                list(((model or {}).get("csf_outcome_records") or {}).get("reviewed_actions") or []),
                list(((model or {}).get("csf_outcome_records") or {}).get("supporting_basis") or []),
                str(((model or {}).get("csf_outcome_records") or {}).get("read_error") or ""),
                int(((model or {}).get("csf_outcome_records") or {}).get("reviewed_action_total") or 0),
                dict((model or {}).get("csf_information_flow") or {}),
                str(active_profile.get("profile_kind") or "organizational") == "organizational",
            )

    function_class = f"csf-function-{csf_section_for_path(current_path)}"
    return f'''<section class="panel csf-explorer csf-explorer-composite {function_class}" aria-label="CSF Category, Subcategory, and NIST implementation examples">
  <div class="csf-explorer-section csf-selection-list" aria-labelledby="csf-explorer-title">
  <div class="csf-explorer-head"><div><div id="csf-explorer-title" class="kicker">{esc(function["title"])} · Categories</div></div></div>
  <div class="csf-explorer-list-panel"><div class="csf-explorer-list" tabindex="0" data-explorer-list="categories" aria-label="{esc(function["title"])} Categories">{category_rows}</div></div>
</div>
  <div class="csf-explorer-section csf-selection-list" aria-labelledby="csf-subcategories-title">
  <div id="csf-subcategories-title" class="kicker">{esc(subcategory_heading)}</div>
  <div class="csf-explorer-list-panel"><div class="csf-explorer-list" tabindex="0" data-explorer-list="subcategories" aria-label="Selected Category Subcategories">{subcategory_content}</div></div>
</div>
  <div class="csf-explorer-section csf-example-region" aria-label="NIST Implementation examples">
  {outcome_content}
</div>
</section>
<section class="panel csf-explorer csf-evidence-workspace" aria-labelledby="csf-evidence-workspace-title">
  <div id="csf-evidence-workspace-title" class="kicker">{esc(assessment_heading)}</div>{evidence_content}
</section>'''


def render_csf_guidance(current_path: str) -> str:
    purpose, use_here = csf_guidance_values(current_path)
    section = csf_section_for_path(current_path)
    function_class = f" csf-function-{section}" if section in CSF_FUNCTION_GUIDANCE else ""
    return (
        f'<div class="csf-guidance{function_class}">'
        f'<strong id="csf-guidance-purpose">{esc(purpose)}</strong>'
        f'<span id="csf-guidance-use">{esc(use_here)}</span>'
        '</div>'
    )


def render_page_shell(model: Dict[str, Any], current_path: str, title: str, lede: str, body_html: str, *, show_technical_nav: bool = False) -> str:
    persona_id = CSF_ANALYST_PERSONA_ID
    persona_profile = coerce_persona_profile((model.get("app") or {}).get("persona_profile") or {"persona_id": persona_id})
    mood = dashboard_mood(model)
    tone = "ok" if mood["tone"] == "calm" else ("medium" if mood["tone"] == "warning" else "high")
    guidance_purpose, guidance_use = csf_guidance_values(current_path)
    csf_profile_context = (model.get("app") or {}).get("csf_profile_context") or {}
    active_csf_profile = csf_profile_context.get("active_profile") or {}
    active_profile_name = str(active_csf_profile.get("profile_name") or "")
    profile_options = "".join(
        f'<option value="{esc(str(profile.get("profile_name") or ""))}"'
        f'{" selected" if str(profile.get("profile_name") or "") == active_profile_name else ""}>'
        f'{esc(csf_profile_picker_label(profile))}</option>'
        for profile in (csf_profile_context.get("defined_profiles") or [])
    )
    profile_selector = f'''<form class="csf-profile-selector" method="post" action="/set-active-csf-profile">
      <input type="hidden" name="return_to" value="{esc(current_path)}">
      <label>Profile<select name="profile_name" onchange="this.form.submit()" aria-label="Active Organizational Profile">{profile_options}</select></label>
    </form>'''
    configuration_routes = {
        "/",
        "/profile",
        "/profile-audit",
        "/profile-creation",
        "/control-catalogs",
        "/evidence",
        "/audit-log",
        "/community-profiles",
    }
    is_configuration_page = current_path in configuration_routes
    mode_link_href = "/govern" if is_configuration_page else "/"
    mode_link_label = "Workspace" if is_configuration_page else "Configure"
    is_csf_explorer_route = current_path in CSF_FUNCTION_ID_BY_ROUTE
    workspace_html = (
        render_csf_explorer(current_path, model.get("csf_explorer_selection"), model)
        if is_csf_explorer_route
        else body_html
    )
    workspace_class = "workspace-scroll csf-explorer-workspace" if is_csf_explorer_route else "workspace-scroll"
    body = f"""
<!-- csf-app:start -->
<div id="csf-app" data-csf-route="{esc(current_path)}" data-csf-guidance-purpose="{esc(guidance_purpose)}" data-csf-guidance-use="{esc(guidance_use)}">
<section class="panel csf-map">
  <header class="app-masthead"><div class="app-title-context"><div class="app-title">Codex Monitor</div>{profile_selector}</div><div class="app-header-actions"><a class="app-home-link" href="{mode_link_href}">{mode_link_label}</a></div></header>
  <div class="kicker">CSF action map</div>
  <nav class="csf-action-bar" aria-label="NIST Cybersecurity Framework actions">{render_primary_nav(current_path, persona_profile=persona_profile, show_technical=show_technical_nav)}</nav>
  {render_csf_guidance(current_path)}
</section>
<main id="csf-workspace" class="csf-workspace" tabindex="-1">
  <div class="{workspace_class}">{workspace_html}</div>
</main>
</div>
<!-- csf-app:end -->
"""
    body = body.replace("Codex Monitor", FRAMEWORK_DISPLAY_NAME, 1)
    return html_page(PRODUCT_DISPLAY_NAME, body)



def extract_csf_app_fragment(document: str) -> str:
    match = re.search(r"<!-- csf-app:start -->(.*?)<!-- csf-app:end -->", document, flags=re.DOTALL)
    if not match:
        raise ValueError("The requested page does not provide a CSF workspace fragment.")
    return match.group(1).strip()


def render_record_modal(
    title: str,
    content_html: str,
    detail_href: str,
    kicker: str = "Evidence detail",
    context_heading: str = "",
) -> str:
    heading = context_heading or title
    return f"""
<div class="modal-backdrop" data-modal-close>
  <section class="modal-dialog" role="dialog" aria-modal="true" aria-labelledby="record-detail-title">
    <div class="modal-head">
      <div><div class="kicker">{esc(kicker)}</div><h2 id="record-detail-title" class="csf-modal-outcome">{esc(heading)}</h2></div>
      <button class="btn" type="button" data-modal-close aria-label="Close detail">Close</button>
    </div>
    <div class="modal-body">{content_html}<div class="task-actions" style="margin-top:14px"><a class="btn" href="{esc(detail_href)}">Open full page</a></div></div>
  </section>
</div>
"""


def render_csf_entry_modal(
    kind: str,
    subcategory_id: str,
    category_id: str,
    return_to: str,
    record: Optional[Dict[str, Any]] = None,
    action_updates: Optional[List[Dict[str, Any]]] = None,
    edit: bool = False,
    mapped_controls: Optional[List[Dict[str, Any]]] = None,
    available_evidence: Optional[List[Dict[str, Any]]] = None,
    subcategory_outcome: str = "",
    profile_assessment: Optional[Dict[str, Any]] = None,
    generic_action_examples: Optional[Dict[str, str]] = None,
    enabled_control_catalog_count: int = 0,
    sample_opportunity: Optional[Dict[str, str]] = None,
    evidence_link_events: Optional[List[Dict[str, Any]]] = None,
) -> str:
    """Render a compact Tile 3 entry form, detail view, or action-update form."""
    is_action = kind == "action"
    title = "Action" if is_action else "Evidence"
    outcome_heading = str(subcategory_outcome or subcategory_id).strip()
    profile_assessment = profile_assessment or {}
    sample_opportunity = sample_opportunity or {}
    opportunity_text = str(sample_opportunity.get("text") or "").strip()
    opportunity_focus = str(sample_opportunity.get("focus_area") or "").strip()
    opportunity_context = (
        '<div style="display:grid;gap:3px;margin-top:8px;padding:7px 9px;border-left:3px solid #5d7f94;border-radius:6px;background:rgba(232,239,245,.54);color:#42555f;font-size:12px;line-height:1.4">'
        f'<strong style="color:#41525a;font-size:11px;text-transform:uppercase;letter-spacing:.05em">NIST sample opportunity{esc(" — " + opportunity_focus if opportunity_focus else "")}</strong>'
        f'<p style="margin:0">{esc(opportunity_text)}</p></div>'
        if is_action and opportunity_text else ""
    )
    linked_control_id = str((record or {}).get("control_id") or "").strip()
    linked_control_title = str((record or {}).get("control_title") or "").strip()
    linked_catalog_name = str((record or {}).get("control_catalog_name") or "Control catalog").strip()
    generic_action_examples = generic_action_examples or {}
    available_evidence = available_evidence or []
    evidence_link_events = evidence_link_events or []
    query = urllib.parse.urlencode({
        "csf_category": category_id,
        "csf_subcategory": subcategory_id,
        "return_to": return_to,
    })
    if record and not edit:
        fields = [("Title", record.get("title")), ("Details", record.get("details"))]
        if is_action:
            fields.extend([
                ("Mapped control", f"NIST SP 800-53: {linked_control_id} - {linked_control_title}" if linked_control_id else "Manual action — no mapped control selected"),
                ("Evidence", "; ".join(str(value) for value in (record.get("basis_titles") or [])) or "No evidence linked directly to this action."),
                ("Why this action?", record.get("rationale")),
                ("Status", str(record.get("action_status") or "").replace("_", " ").title()),
                ("Created", pretty_time(record.get("created_at"))),
                ("Last updated", pretty_time(record.get("updated_at"))),
                ("Completed", pretty_time(record.get("completed_at"))),
            ])
            history_rows = "".join(
                f'<div class="csf-record-row"><strong>{esc(str(item.get("action_status") or "").replace("_", " ").title())}</strong><span>{esc(pretty_time(item.get("recorded_at")))} · {esc(item.get("progress_note") or "No progress note.")}{(" · Evidence: " + esc(", ".join(str(value) for value in (item.get("basis_titles") or []))) if item.get("basis_titles") else "")}</span></div>'
                for item in (action_updates or [])
            ) or '<p class="csf-record-empty">No progress updates are recorded yet.</p>'
            evidence_link_rows = "".join(
                f'<div class="csf-record-row"><strong>{esc(str(item.get("event_type") or "").title())}: {esc(str(item.get("evidence_title") or "Untitled evidence"))}</strong><span>{esc(pretty_time(item.get("recorded_at")))} · {esc(str(item.get("recorded_by") or "Unknown user"))}</span></div>'
                for item in evidence_link_events
            ) or '<p class="csf-record-empty">No evidence-link changes are recorded yet.</p>'
            edit_href = f'/csf-reviewed-action?{query}&amp;action_id={urllib.parse.quote(str(record.get("action_id") or ""), safe="")}&amp;edit=1'
            content = (
                '<dl class="kv">' + ''.join(f'<dt>{esc(label)}</dt><dd>{esc(value or "—")}</dd>' for label, value in fields) + '</dl>'
                + f'<div class="csf-record-list-head" style="margin-top:16px"><strong>Previous updates</strong><a class="btn" data-record-modal href="{edit_href}">Edit action</a></div>'
                + f'<div class="csf-record-list" tabindex="0" aria-label="Previous action updates">{history_rows}</div>'
                + '<div class="csf-record-list-head" style="margin-top:16px"><strong>Evidence link history</strong></div>'
                + f'<div class="csf-record-list" tabindex="0" aria-label="Evidence link history">{evidence_link_rows}</div>'
            )
        else:
            fields.extend([
                ("Reference location", record.get("reference_location")),
                ("Date on the evidence", record.get("recorded_on")),
                ("Review on", record.get("review_on")),
                ("Recorded in the workspace", pretty_time(record.get("created_at"))),
                ("Last updated", pretty_time(record.get("updated_at"))),
            ])
            content = '<dl class="kv">' + ''.join(f'<dt>{esc(label)}</dt><dd>{esc(value or "—")}</dd>' for label, value in fields) + '</dl>'
        return render_record_modal(
            title,
            content,
            return_to,
            f"{title} · {subcategory_id}",
            outcome_heading,
        )
    action = "/update-csf-reviewed-action" if is_action and record else ("/create-csf-reviewed-action" if is_action else "/create-csf-supporting-basis")
    action += "?" + urllib.parse.urlencode({
        "csf_category": category_id,
        "csf_subcategory": subcategory_id,
        "return_to": return_to,
    })
    delete_action = ""
    if is_action and record:
        record_id_query = urllib.parse.quote(str(record.get("action_id") or ""), safe="")
        action += "&action_id=" + record_id_query
        delete_action = f"/delete-csf-reviewed-action?{query}&action_id={record_id_query}"
    hidden = f'{opportunity_context}<input type="hidden" name="subcategory_id" value="{esc(subcategory_id)}"><input type="hidden" name="category_id" value="{esc(category_id)}"><input type="hidden" name="return_to" value="{esc(return_to)}">'
    if is_action:
        status = str((record or {}).get("action_status") or "planned")
        action_id = str((record or {}).get("action_id") or "")
        status_buttons = "".join(
            f'<label class="csf-status-choice"><input type="radio" name="action_status" value="{value}"{" checked" if status == value else ""}>{label}</label>'
            for value, label in (("planned", "Planned"), ("in_progress", "In progress"), ("completed", "Completed"), ("not_proceeding", "Not proceeding"))
        )
        control_picker = ""
        if not record and (mapped_controls or enabled_control_catalog_count > 0):
            def render_mapped_control_row(item: Dict[str, Any]) -> str:
                confidence_note = str(item.get("confidence_note") or "").strip()
                confidence_html = (
                    f'<p class="csf-control-confidence"><b>Review note:</b> {esc(confidence_note)}</p>'
                    if confidence_note else ""
                )
                recorded_action_html = (
                    "<small>Action already recorded: " + esc(item.get("action_title") or "Untitled action")
                    + " (" + esc(str(item.get("action_status") or "").replace("_", " ").title()) + ")</small>"
                    if item.get("action_id") else ""
                )
                return f'''<label class="csf-control-choice{(" unavailable" if item.get("action_id") else "")}">
<input type="radio" name="control_mapping" value="{esc(str(item.get("framework_id") or ""))}|{esc(str(item.get("control_id") or ""))}" data-action-title-example="{esc(item.get("action_title_example") or "")}" data-action-details-example="{esc(item.get("action_details_example") or item.get("suggested_action_text") or "")}" data-action-rationale-example="{esc(item.get("action_rationale_example") or "")}"{" disabled" if item.get("action_id") else ""}>
<div class="csf-control-content"><strong>{esc(item.get("catalog_name") or "Control catalog")}: {esc(item.get("control_id") or "")}</strong><span class="csf-control-title">{esc(item.get("title") or "")}</span><p class="csf-control-interpretation"><b>How it applies here:</b> {esc(item.get("interpretation_text") or "A product interpretation has not been recorded for this mapping yet.")}</p><p class="csf-control-action"><b>Possible action:</b> {esc(item.get("suggested_action_text") or "Choose a locally appropriate action that advances this CSF outcome.")}</p>{confidence_html}<details class="csf-control-official"><summary>Official control statement</summary><p>{esc(item.get("statement_text") or "Official control statement is not imported yet.")}</p></details>{recorded_action_html}</div>
</label>'''
            control_rows = "".join(
                render_mapped_control_row(item)
                for item in (mapped_controls or [])
            ) or '<p class="csf-record-empty">No enabled catalog has a control mapped to this CSF Subcategory. You can still add an action by hand.</p>'
            control_picker = f'''<fieldset class="csf-control-picker"><legend>Mapped controls <span>(optional)</span></legend><p class="mini">Choose one control to show outcome-specific examples in the action fields, or leave this unselected to add an action by hand. Edit the Profile to change its enabled control catalogs.</p><div class="csf-control-list csf-mapped-control-list" tabindex="0" aria-label="Mapped controls">{control_rows}</div></fieldset>'''
        evidence_picker = ""
        if available_evidence and not record:
            evidence_rows = "".join(
                f'''<label class="csf-control-choice"><input type="checkbox" name="basis_id" value="{esc(str(item.get("basis_id") or ""))}">
<div class="csf-control-content"><strong>{esc(str(item.get("title") or "Untitled evidence"))}</strong><span class="csf-control-title">{esc(str(item.get("basis_type") or "").replace("_", " ").title())}</span><p class="csf-control-interpretation">Recorded {esc(str(item.get("recorded_on") or "date not recorded"))} · Review {esc(str(item.get("review_on") or "date not set"))}</p></div></label>'''
                for item in available_evidence
            )
            evidence_picker = f'''<fieldset class="csf-control-picker"><legend>Evidence <span>(optional)</span></legend><p class="mini">Select existing evidence that supports this action. Evidence remains stored once and can support other work in this Profile.</p><div class="csf-control-list csf-action-evidence-list" tabindex="0" aria-label="Available evidence">{evidence_rows}</div></fieldset>'''
        update_evidence_picker = ""
        if available_evidence and record:
            direct_evidence_ids = set(str(value) for value in (record.get("basis_ids") or []))
            update_evidence_rows = "".join(
                f'''<label class="csf-control-choice"><input type="checkbox" name="basis_id" value="{esc(str(item.get("basis_id") or ""))}{'" checked' if str(item.get("basis_id") or "") in direct_evidence_ids else '"'}>
<div class="csf-control-content"><strong>{esc(str(item.get("title") or "Untitled evidence"))}</strong><span class="csf-control-title">{esc(str(item.get("basis_type") or "").replace("_", " ").title())}</span></div></label>'''
                for item in available_evidence
            )
            update_evidence_picker = f'''<fieldset class="csf-control-picker"><legend>Evidence supporting this action <span>(optional)</span></legend><p class="mini">Select evidence that supports this action and the update you are recording now.</p><div class="csf-control-list" tabindex="0" aria-label="Evidence supporting this action">{update_evidence_rows}</div></fieldset>'''
        fields = f'''<input type="hidden" name="action_id" value="{esc(action_id)}">
{control_picker}
{evidence_picker}
{(f'<div class="csf-linked-control"><strong>Mapped control</strong><span>NIST SP 800-53: {esc(linked_control_id)} - {esc(linked_control_title or "Title unavailable")}</span></div>' if linked_control_id else ('<div class="csf-linked-control manual"><strong>Action origin</strong><span>Manual action — no mapped NIST SP 800-53 control selected.</span></div>' if record else ''))}
<label>Action title<input name="title" required maxlength="240" value="{esc((record or {}).get("title") or "")}" placeholder="Example: {esc(generic_action_examples.get("title") or "Enable BitLocker on the laptop")}"></label>
<label>Action details<textarea name="details" placeholder="Example: {esc(generic_action_examples.get("details") or "Describe what will be done and how.")}">{esc((record or {}).get("details") or "")}</textarea></label>
<label>Why this action?<textarea name="rationale" placeholder="Example: {esc(generic_action_examples.get("rationale") or "Explain why this supports the CSF outcome.")}">{esc((record or {}).get("rationale") or "")}</textarea></label>
<fieldset class="csf-status-options"><legend>Status</legend>{status_buttons}</fieldset>
<label>Progress note<textarea name="progress_note" placeholder="What changed since the last update? Example: Recovery key verified and stored in the approved location."></textarea></label>
{update_evidence_picker}'''
    else:
        fields = f'''<fieldset class="csf-control-picker"><legend>Evidence artifact</legend>
<label>Evidence title<input name="title" required maxlength="240" placeholder="Example: Current mission statement"></label>
<label>Evidence type<select name="basis_type"><option value="document">Document</option><option value="local_evidence">Local evidence</option><option value="attestation">Attestation</option><option value="decision_note">Decision note</option><option value="other">Other</option></select></label>
<label>What does this evidence show?<textarea name="details" placeholder="Example: The approved mission statement and the date it was shared with staff."></textarea></label>
<label>Reference location<input name="reference_location" placeholder="Example: C:\\Evidence\\mission-statement.pdf"></label>
<label>What is the date on the evidence?<input type="date" name="recorded_on"></label><label>Review this evidence on<input type="date" name="review_on"></label></fieldset>
<fieldset class="csf-control-picker"><legend>Supporting basis: How this supports {esc(subcategory_id)}</legend>
<label>Supports<select name="outcome_link_role"><option value="supports_outcome" selected>This outcome</option><option value="supports_current_assessment">The current assessment</option><option value="supports_target_rationale">The target rationale</option></select></label>
<label>Assertion<textarea name="assertion_text" placeholder="What specific claim does this evidence support?"></textarea></label>
<label><span>Applicability or limitation note <span class="mini">(optional)</span></span><textarea name="applicability_note" placeholder="Why does this evidence apply here, or what should the reviewer keep in mind?"></textarea></label></fieldset>'''
    form_heading = f'Edit {title}' if record else f'Add {title}'
    save_label = "Save update" if is_action and record else f"Save {title}"
    delete_control = f'<button class="btn" type="submit" formmethod="post" formaction="{esc(delete_action)}" data-confirm-delete>Delete action</button>' if delete_action else ""
    return f'''<div class="modal-backdrop" data-modal-close><section class="modal-dialog" role="dialog" aria-modal="true" aria-labelledby="record-detail-title"><div class="modal-head"><div><div class="kicker">{esc(form_heading)} · {esc(subcategory_id)}</div><h2 id="record-detail-title" class="csf-modal-outcome">{esc(outcome_heading)}</h2></div><button class="btn" type="button" data-modal-close>Close</button></div><div class="modal-body"><form class="csf-entry-form" method="post" action="{action}">{hidden}{fields}<div class="task-actions"><button class="btn primary" type="submit">{save_label}</button>{delete_control}</div></form></div></section></div>'''


def render_record_payload(title: str, subtitle: str, payload_text: str) -> str:
    return f'<section class="panel stack"><div class="kicker">{esc(subtitle)}</div><h2>{esc(title)}</h2><pre>{esc(payload_text)}</pre></section>'


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
    top_report = model["reports"]["top"]
    active_profile = (snapshot.get("csf_profile_context") or {}).get("active_profile") or {}
    active_profile_name = str(active_profile.get("profile_name") or "")
    active_profile_url = "/profile?name=" + urllib.parse.quote(active_profile_name, safe="")
    profile_source_summary = render_active_profile_source(active_profile)
    profile_controls_summary = render_active_profile_controls(config.state_db_path, active_profile.get("profile_id"))
    body = f"""
<section class="dashboard-start-tiles">
  <div class="panel stack">
    <div class="kicker">Current profile</div>
    <div class="csf-community-profile-list">{profile_source_summary}</div>
    {profile_controls_summary}
    <div class="task-actions">
      <a class="btn primary" href="{esc(active_profile_url)}">Edit current profile</a>
      <a class="btn primary" href="/profile-creation">Add new profile</a>
      <button class="btn" type="button" disabled title="Plans will be added as a separate configuration screen.">Plans</button>
    </div>
  </div>
  <div class="panel stack">
    <div class="kicker">Catalogs</div>
    <div class="csf-record-list-head"><strong>Community Profiles</strong></div>
    <div class="mini">Browse frozen Community Profile sources that can inform an Organizational Profile.</div>
    <div class="task-actions"><a class="btn primary" href="/community-profiles">Profiles catalogs</a></div>
    <div class="csf-record-list-head"><strong>Control catalogs</strong></div>
    <div class="mini">Browse the control frameworks available for a Profile to select.</div>
    <div class="task-actions"><a class="btn primary" href="/control-catalogs">Control catalogs</a></div>
  </div>
  {render_configuration_records_tile(config, model, top_report)}
</section>
"""
    return render_page_shell(model, "/", "CSF Analyst", "Choose how this workspace is configured, automated, and documented.", body, show_technical_nav=persona_allows_diagnostics(config.ui_persona))


def render_configuration_records_tile(config: AppConfig, model: Dict[str, Any], top_report: Optional[Dict[str, Any]]) -> str:
    """Keep the analyst configuration page free of monitoring operations."""
    if config.app_mode == "analyst":
        return '''<div class="panel stack">
    <div class="kicker">Records</div>
    <div class="mini">Review the evidence and append-only audit history that support this Profile.</div>
    <div class="task-actions"><a class="btn" href="/evidence">Evidence library</a><a class="btn" href="/audit-log">View audit log</a></div>
  </div>'''
    attention = int((model.get("task_job_health") or {}).get("attention_tasks") or 0)
    return f'''<div class="panel stack">
    <div class="kicker">Automation</div>
    <h2>Keep local work running</h2>
    <div class="focus-card {'calm' if attention == 0 else 'warning'}">
      <div class="focus-label">Scheduled work</div>
      <div class="focus-title">{esc('All scheduled jobs are running' if attention == 0 else f"{attention} job(s) need attention")}</div>
      <div class="focus-copy">Automation collects and refreshes the local information this workspace uses.</div>
    </div>
    <div class="task-actions"><a class="btn" href="/govern">Review automation</a></div>
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
    <div class="task-actions"><a class="btn" href="/reports">Open reports</a></div>
  </div>'''


def render_control_catalogs_page(config: AppConfig, snapshot: Dict[str, Any], message: str = "") -> str:
    """Render the framework-neutral catalog selection page."""
    connection = ioc_store.connect_db(config.state_db_path)
    try:
        ioc_store.init_db(connection)
        active_profile = ioc_store.get_active_csf_profile(connection)
        catalogs = ioc_store.list_csf_profile_control_catalogs(connection, active_profile.get("profile_id"))
    finally:
        connection.close()
    rows = "".join(
        f'''<label class="focus-card" style="display:grid;gap:8px;cursor:pointer">
  <span><input type="checkbox" name="framework_id" value="{esc(str(catalog['framework_id']))}"{' checked' if int(catalog['profile_is_enabled']) else ''}{' disabled' if str(active_profile.get('profile_kind') or '') != 'organizational' else ''}> <strong>{esc(str(catalog['display_name']))}</strong>{(' · ' + esc(str(catalog['version']))) if catalog['version'] else ''}</span>
  <span class="mini">{esc(str(catalog['control_count']))} imported controls · {esc(str(catalog['mapping_count']))} CSF mappings</span>
  <span class="mini">{esc(str(catalog['source_label']))}</span>
</label>'''
        for catalog in catalogs
    ) or '<p class="mini">No control catalogs are registered yet.</p>'
    body = f'''
<section class="panel stack">
  <div class="kicker">Configuration</div>
  <h2>Control catalogs</h2>
  <div class="mini">Select the control catalogs available in the Tile 3 action picker for <strong>{esc(str(active_profile.get('profile_name') or 'this Profile'))}</strong>. Clearing a selection does not remove imported controls, mappings, or actions already linked to them.</div>
  <form class="stack" method="post" action="/set-csf-control-catalogs">
    <div class="care-list">{rows}</div>
    <div class="task-actions">{('<button class="btn primary" type="submit">Save catalog selection</button>' if str(active_profile.get('profile_kind') or '') == 'organizational' else '<span class="mini">Frozen Community and base Profiles are read-only.</span>')}<a class="btn" href="/">Back to workspace</a></div>
  </form>
</section>'''
    model = build_dashboard_model(config, snapshot, message)
    return render_page_shell(model, "/control-catalogs", "Control catalogs", "Choose the control frameworks used by the active Profile.", body, show_technical_nav=persona_allows_diagnostics(config.ui_persona))


def render_control_catalogs_page(config: AppConfig, snapshot: Dict[str, Any], message: str = "") -> str:
    """Render available framework sources; Profiles make their own selections."""
    connection = ioc_store.connect_db(config.state_db_path)
    try:
        ioc_store.init_db(connection)
        catalogs = ioc_store.list_csf_control_catalogs(connection)
    finally:
        connection.close()
    rows = "".join(
        f'''<div class="focus-card" style="display:grid;gap:8px">
  <strong>{esc(" ".join(part for part in (str(catalog.get("display_name") or "").strip(), str(catalog.get("version") or "").strip()) if part))}</strong>
  <span class="mini">{esc(str(catalog.get("control_count") or 0))} imported controls; {esc(str(catalog.get("mapping_count") or 0))} CSF mappings</span>
  <span class="mini">{esc(str(catalog.get("source_label") or ""))}</span>
</div>'''
        for catalog in catalogs
    ) or '<p class="mini">No control catalogs are registered yet.</p>'
    body = f'''<section class="panel stack">
  <div class="kicker">Configuration</div><h2>Control catalogs</h2>
  <div class="mini">These control-framework sources are available for a Profile to select. Choose a Profile's control set when creating or editing that Profile.</div>
  <div class="care-list">{rows}</div>
  <div class="task-actions"><a class="btn" href="/">Back to workspace</a></div>
</section>'''
    model = build_dashboard_model(config, snapshot, message)
    return render_page_shell(model, "/control-catalogs", "Control catalogs", "Browse the control-framework sources a Profile may use.", body, show_technical_nav=persona_allows_diagnostics(config.ui_persona))


def render_evidence_library_page(
    config: AppConfig, snapshot: Dict[str, Any], message: str = "", basis_id: str = ""
) -> str:
    """Render the selected Profile's reusable evidence artifacts and their use counts."""
    active_profile = (snapshot.get("csf_profile_context") or {}).get("active_profile") or {}
    profile_id = str(active_profile.get("profile_id") or "")
    connection = ioc_store.connect_db(config.state_db_path)
    try:
        ioc_store.init_db(connection)
        evidence = ioc_store.list_csf_evidence_library(connection, profile_id)
        detail = ioc_store.get_csf_evidence_detail(connection, profile_id, basis_id) if basis_id else None
    finally:
        connection.close()
    rows = "".join(
        f'''<a class="csf-record-row" href="/evidence?basis_id={urllib.parse.quote(str(item.get("basis_id") or ""), safe="")}"><strong>{esc(str(item.get("title") or "Untitled evidence"))}</strong>
  <span>{esc(str(item.get("basis_type") or "").replace("_", " ").title())} · {esc(str(item.get("outcome_link_count") or 0))} outcome use(s) · {esc(str(item.get("action_link_count") or 0))} action use(s) · {esc(str(item.get("action_update_link_count") or 0))} update use(s)</span>
  <span>{esc("Recorded " + str(item.get("recorded_on")) if item.get("recorded_on") else "No recorded-on date")} · {esc("Review " + str(item.get("review_on")) if item.get("review_on") else "No review date")}</span></a>'''
        for item in evidence
    ) or '<p class="csf-record-empty">No evidence is recorded for this Profile yet. Add it from an outcome in the Workspace.</p>'
    detail_html = ""
    if detail:
        artifact = detail["evidence"]
        outcome_rows = "".join(
            f'<div class="csf-record-row"><strong>{esc(str(item.get("subcategory_id") or ""))}</strong><span>{esc(str(item.get("link_role") or "").replace("_", " ").title())}{(" · " + esc(str(item.get("assertion_text"))) if item.get("assertion_text") else "")}</span></div>'
            for item in detail["outcome_uses"]
        ) or '<p class="csf-record-empty">Not linked to an outcome.</p>'
        action_rows = "".join(
            f'<div class="csf-record-row"><strong>{esc(str(item.get("subcategory_id") or ""))}: {esc(str(item.get("title") or "Untitled action"))}</strong><span>{esc(str(item.get("action_status") or "").replace("_", " ").title())}{(" · " + esc(str(item.get("assertion_text"))) if item.get("assertion_text") else "")}</span></div>'
            for item in detail["action_uses"]
        ) or '<p class="csf-record-empty">Not linked directly to an action.</p>'
        update_rows = "".join(
            f'<div class="csf-record-row"><strong>{esc(str(item.get("subcategory_id") or ""))}: {esc(str(item.get("title") or "Untitled action"))}</strong><span>{esc(pretty_time(item.get("recorded_at")))} · {esc(str(item.get("progress_note") or "No progress note."))}</span></div>'
            for item in detail["action_update_uses"]
        ) or '<p class="csf-record-empty">Not linked to an action update.</p>'
        detail_html = f'''<section class="panel stack">
  <div class="kicker">Evidence detail</div><h2>{esc(str(artifact.get("title") or "Untitled evidence"))}</h2>
  <dl class="kv"><dt>Type</dt><dd>{esc(str(artifact.get("basis_type") or "").replace("_", " ").title())}</dd><dt>Details</dt><dd>{esc(str(artifact.get("details") or "—"))}</dd><dt>Reference location</dt><dd>{esc(str(artifact.get("reference_location") or "—"))}</dd><dt>Recorded on</dt><dd>{esc(str(artifact.get("recorded_on") or "—"))}</dd><dt>Review on</dt><dd>{esc(str(artifact.get("review_on") or "—"))}</dd></dl>
  <div class="csf-record-list-head"><strong>Used by outcomes</strong></div><div class="csf-record-list">{outcome_rows}</div>
  <div class="csf-record-list-head"><strong>Used by actions</strong></div><div class="csf-record-list">{action_rows}</div>
  <div class="csf-record-list-head"><strong>Used by action updates</strong></div><div class="csf-record-list">{update_rows}</div>
  <div class="task-actions"><a class="btn" href="/evidence">Back to evidence library</a></div>
</section>'''
    body = detail_html or f'''<section class="panel stack">
  <div class="kicker">Current profile</div>
  <h2>Evidence library</h2>
  <div class="mini">Each evidence artifact is stored once and can be linked to multiple outcomes, actions, and action updates in this Profile. Each use can carry its own assertion, applicability, and review note.</div>
  <div class="csf-record-list" tabindex="0" aria-label="Evidence library">{rows}</div>
  <div class="task-actions"><a class="btn" href="/">Back to configuration</a></div>
</section>'''
    model = build_dashboard_model(config, snapshot, message)
    return render_page_shell(model, "/evidence", "Evidence library", "Review evidence artifacts and how they are used in the active Profile.", body, show_technical_nav=persona_allows_diagnostics(config.ui_persona))


def render_audit_log_page(
    config: AppConfig, snapshot: Dict[str, Any], log_selection: str = "all"
) -> str:
    """Render the active Profile's combined, read-only audit ledger."""
    allowed_selections = {"all", "profile", "assessment", "evidence", "action"}
    selected = log_selection if log_selection in allowed_selections else "all"
    active_profile = (snapshot.get("csf_profile_context") or {}).get("active_profile") or {}
    profile_id = str(active_profile.get("profile_id") or "")
    connection = ioc_store.connect_db(config.state_db_path)
    try:
        ioc_store.init_db(connection)
        rows = ioc_store.list_csf_profile_activity_log(connection, profile_id)
    finally:
        connection.close()
    if selected != "all":
        rows = [row for row in rows if str(row.get("log_kind") or "") == selected]
    def audit_event_label(item: Dict[str, Any]) -> str:
        """Use a clear creation label without widening the audit-event schema."""
        event_type = str(item.get("event_type") or "")
        summary = str(item.get("summary") or "")
        if (
            str(item.get("log_kind") or "") == "evidence"
            and event_type == "evidence_linked"
            and summary.startswith("Evidence created")
        ):
            event_type = "evidence_created"
        return f'{str(item.get("log_kind") or "").title()}: {event_type.replace("_", " ").title()}'

    log_rows = "".join(
        f'''<div class="csf-record-row"><strong>{esc(audit_event_label(item))} · {esc(str(item.get("subject") or ""))}</strong>
<span>{esc(pretty_time(item.get("recorded_at")))} · {esc(str(item.get("recorded_by") or "Unknown user"))} · {esc(str(item.get("summary") or "No additional detail."))}</span></div>'''
        for item in rows
    ) or '<p class="csf-record-empty">No matching audit events are recorded for this Profile yet.</p>'
    options = "".join(
        f'<option value="{value}"{" selected" if selected == value else ""}>{label}</option>'
        for value, label in (
            ("all", "All logs"),
            ("profile", "Profile changes"),
            ("assessment", "Current assessments"),
            ("evidence", "Evidence links"),
            ("action", "Action updates"),
        )
    )
    body = f'''<section class="panel stack">
  <div class="kicker">Reports</div><h2>Audit log</h2>
  <div class="mini">Append-only activity for <strong>{esc(str(active_profile.get("profile_name") or "the active Profile"))}</strong>.</div>
  <form class="csf-profile-selector" method="get" action="/audit-log" style="margin-left:0"><label>Log selection<select name="log" onchange="this.form.submit()">{options}</select></label></form>
  <div class="csf-record-list" style="height:520px" tabindex="0" aria-label="Audit log">{log_rows}</div>
  <div class="task-actions"><a class="btn" href="/">Back to configuration</a></div>
</section>'''
    model = build_dashboard_model(config, snapshot, "")
    return render_page_shell(model, "/audit-log", "Audit log", "Review profile activity across assessments, evidence, actions, and tailoring.", body, show_technical_nav=persona_allows_diagnostics(config.ui_persona))


def render_csf_profile_picker(profile_context: Dict[str, Any], return_to: str = "/") -> str:
    """Render the reusable Profile selection control used in Configuration."""
    active = profile_context.get("active_profile") or {}
    active_name = str(active.get("profile_name") or "")
    rows = "".join(
        f'''<label class="csf-profile-choice">
  <input type="radio" name="profile_name" value="{esc(str(profile.get('profile_name') or ''))}"{' checked' if str(profile.get('profile_name') or '') == active_name else ''}>
  <span>{esc(csf_profile_picker_label(profile))}</span>
</label>'''
        for profile in (profile_context.get("defined_profiles") or [])
    ) or '<p class="csf-record-empty">No profiles are defined.</p>'
    return f'''<form class="csf-entry-form" method="post" action="/set-active-csf-profile"><input type="hidden" name="return_to" value="{esc(return_to)}"><div class="csf-record-list csf-profile-picker-list" tabindex="0" aria-label="Profiles">{rows}</div><div class="task-actions"><button class="btn primary" type="submit">Use selected profile</button><a class="btn" href="/profile?name={urllib.parse.quote(active_name, safe='')}">Open active profile</a></div></form>'''


def render_csf_profiles_modal(profile_context: Dict[str, Any], return_to: str = "/") -> str:
    """Retain the Profile chooser for bookmarked legacy modal routes."""
    picker = render_csf_profile_picker(profile_context, return_to)
    return f'''<div class="modal-backdrop" data-modal-close>
  <section class="modal-dialog" role="dialog" aria-modal="true" aria-labelledby="csf-profiles-title">
    <div class="modal-head"><div><div class="kicker">Configuration</div><h2 id="csf-profiles-title">Profiles</h2></div><div class="modal-head-actions"><a class="csf-add-record" aria-label="Add profile" href="/profile-creation">+</a><button class="btn" type="button" data-modal-close>Close</button></div></div>
    <div class="modal-body"><p class="mini">Choose the profile that sets the context for the CSF work you are viewing.</p>{picker}</div>
  </section>
</div>'''


def render_community_profiles_page(config: AppConfig, snapshot: Dict[str, Any], message: str = "") -> str:
    """Render the sourced index of CSF 2.0 Community Profiles, not their contents."""
    profile_context = snapshot.get("csf_profile_context") or {}
    rows = "".join(
        f'''<a class="csf-record-row" href="{esc(str(profile.get('source_url') or ''))}" target="_blank" rel="noreferrer">
  <strong>{esc(community_profile_catalog_label(profile))}</strong>
  <span>{esc(str(profile.get('publisher') or ''))} · {esc(str(profile.get('publication_status') or 'See source'))} · {esc(str(profile.get('focus') or ''))}</span>
</a>'''
        for profile in (profile_context.get("community_profiles") or [])
    ) or '<p class="csf-record-empty">No Community Profiles are in the local catalog.</p>'
    body = f'''<section class="panel stack">
  <div class="kicker">Configuration</div>
  <h2>Community Profiles</h2>
  <div class="mini">This catalog lists Community Profiles that are already imported locally as frozen, read-only source artifacts. A Community Profile can inform an Organizational Target Profile; it is not your organization’s assessment.</div>
  <div class="csf-record-list" style="height:auto;max-height:none">{rows}</div>
  <div class="task-actions"><a class="btn" href="/">Back to workspace</a><a class="btn" href="{esc(str((profile_context.get('community_profiles') or [{}])[0].get('catalog_source_url') or 'https://www.nist.gov/cyberframework/profiles'))}" target="_blank" rel="noreferrer">Open NIST catalog</a></div>
</section>'''
    model = build_dashboard_model(config, snapshot, message)
    return render_page_shell(
        model, "/community-profiles", "Community Profiles",
        "Browse a source-traceable catalog before choosing a baseline to tailor.", body,
        show_technical_nav=persona_allows_diagnostics(config.ui_persona),
    )


def render_new_csf_profile_modal(
    community_profiles: List[Dict[str, Any]], return_to: str = "/"
) -> str:
    """Render the small form used to define a new Organizational Profile."""
    community_profile_options = "".join(
        f'<option value="{esc(str(profile.get("community_profile_id") or ""))}">{esc(community_profile_catalog_label(profile))} — {esc(str(profile.get("publisher") or ""))}</option>'
        for profile in community_profiles
    )
    return f'''<div class="modal-backdrop" data-modal-close>
  <section class="modal-dialog" role="dialog" aria-modal="true" aria-labelledby="new-csf-profile-title">
    <div class="modal-head"><div><div class="kicker">Configuration</div><h2 id="new-csf-profile-title">New profile</h2></div><button class="btn" type="button" data-modal-close>Close</button></div>
    <div class="modal-body"><p class="mini">A profile defines the context and the CSF outcomes being tailored for that work.</p><form class="csf-entry-form" method="post" action="/create-csf-profile"><input type="hidden" name="return_to" value="{esc(return_to)}"><label>Profile name<input name="profile_name" required maxlength="120" placeholder="Example: Customer-data handling"></label><label>Context<textarea name="context_summary" required maxlength="1000" placeholder="Example: A single user PC that handles customer information."></textarea></label><label>Community Profile baseline <span class="mini">(optional)</span><select name="community_profile_id"><option value="">No Community Profile selected</option>{community_profile_options}</select></label><div class="task-actions"><button class="btn primary" type="submit">Create profile</button></div></form></div>
  </section>
</div>'''


def render_profile_creation_page(config: AppConfig, snapshot: Dict[str, Any]) -> str:
    """Create an independent Organizational Profile from the NIST base and one optional overlay."""
    profiles = (snapshot.get("csf_profile_context") or {}).get("community_profiles") or []
    options = "".join(
        f'<option value="{esc(str(row.get("community_profile_id") or ""))}">{esc(community_profile_catalog_label(row))} — {esc(str(row.get("publisher") or ""))}</option>'
        for row in profiles
    )
    body = f'''<section class="panel stack"><div class="kicker">Configuration</div><h2>Create Organizational Profile</h2><div class="mini"><strong>Step 1 — NIST CSF 2.0 base.</strong> This profile starts as an independent copy of all official Categories and Subcategories. <strong>Step 2 — optional Community Profile overlay.</strong> Select one published baseline to tailor its priority outcomes for this profile. The new profile remains independent after creation.</div><form class="csf-entry-form" method="post" action="/create-csf-profile"><input type="hidden" name="return_to" value="/"><label>Profile name<input name="profile_name" required maxlength="120" placeholder="Example: Customer-data handling"></label><label>Context<textarea name="context_summary" required maxlength="1000" placeholder="Example: A single user PC that handles customer information."></textarea></label><label>Community Profile overlay <span class="mini">(optional)</span><select name="community_profile_id"><option value="">NIST CSF 2.0 base only</option>{options}</select></label><div class="task-actions"><button class="btn primary" type="submit">Create independent profile</button><a class="btn" href="/">Cancel</a></div></form></section>'''
    organizational_options = "".join(
        f'<option value="{esc(str(row.get("profile_id") or ""))}">{esc(str(row.get("profile_name") or ""))}</option>'
        for row in (snapshot.get("csf_profile_context") or {}).get("defined_profiles") or []
    )
    connection = ioc_store.connect_db(config.state_db_path)
    try:
        ioc_store.init_db(connection)
        catalogs = ioc_store.list_csf_control_catalogs(connection)
    finally:
        connection.close()
    catalog_choices = "".join(
        f'''<label class="csf-status-choice"><input type="checkbox" name="framework_id" value="{esc(str(catalog.get("framework_id") or ""))}"{' checked' if int(catalog.get("is_enabled") or 0) else ''}> {esc(" ".join(part for part in (str(catalog.get("display_name") or "").strip(), str(catalog.get("version") or "").strip()) if part))}</label>'''
        for catalog in catalogs
    ) or '<span class="mini">No control catalogs are imported in this workspace.</span>'
    body = f'''<section class="panel stack"><div class="kicker">Configuration</div><h2>Create Organizational Profile</h2><div class="mini">Start from the frozen NIST base, a frozen Community Profile, or an existing Organizational Profile. The new profile is an independent copy after creation.</div><form class="csf-entry-form" method="post" action="/create-csf-profile"><input type="hidden" name="return_to" value="/"><label>Profile name<input name="profile_name" required maxlength="120" placeholder="Example: Customer-data handling"></label><label>Context<textarea name="context_summary" required maxlength="1000" placeholder="Example: A single user PC that handles customer information."></textarea></label><label>Community Profile source <span class="mini">(optional, read-only)</span><select name="community_profile_id"><option value="">NIST CSF 2.0 base</option>{options}</select></label><label>Copy an Organizational Profile <span class="mini">(optional; takes precedence)</span><select name="source_profile_id"><option value="">Do not copy an Organizational Profile</option>{organizational_options}</select></label><fieldset class="csf-control-picker"><legend>Control catalogs <span>(optional)</span></legend><p class="mini">Choose the control frameworks available for mapped action guidance in this new Profile.</p><div class="csf-status-options">{catalog_choices}</div></fieldset><div class="task-actions"><button class="btn primary" type="submit">Create independent profile</button><a class="btn" href="/">Cancel</a></div></form></section>'''
    return render_page_shell(build_dashboard_model(config, snapshot, ""), "/profile-creation", "Create profile", "Choose a frozen or Organizational source, then create an independent profile.", body, show_technical_nav=persona_allows_diagnostics(config.ui_persona))


def render_profile_editor_page(
    config: AppConfig,
    snapshot: Dict[str, Any],
    profile: Dict[str, Any],
    events: List[Dict[str, Any]],
    outcomes: List[Dict[str, Any]],
    control_catalogs: Optional[List[Dict[str, Any]]] = None,
    saved_outcome_id: str = "",
) -> str:
    profile_kind = str(profile.get("profile_kind") or "organizational")
    editable = profile_kind == "organizational"
    profile_label = {
        "frozen_community": "Community Profile",
        "frozen_base": "NIST CSF Base Profile",
    }.get(profile_kind, "Organizational Profile")
    change_labels = {
        "profile_status": "Profile status",
        "target_assessment_level": "Target assessment",
        "control_catalogs": "Control catalogs",
    }
    value_labels = {
        "not_selected": "Not selected", "included": "Included", "inherited": "Inherited",
        "out_of_scope": "Out of scope", "fully_implemented": "Fully implemented",
        "partly_implemented": "Partly implemented", "not_implemented": "Not implemented",
        "not_applicable": "Not applicable",
    }
    def audit_change(event: Dict[str, Any]) -> str:
        field = str(event.get("field_name") or "")
        if not field:
            return str(event.get("event_type") or "").replace("_", " ").title()
        def audit_value(raw: Any) -> str:
            if raw in (None, ""):
                return "No target" if field == "target_assessment_level" else "None"
            try:
                parsed = json.loads(str(raw))
            except (TypeError, ValueError):
                parsed = raw
            if parsed is None:
                return "No target" if field == "target_assessment_level" else "None"
            text = str(parsed)
            return value_labels.get(text, text)
        return f'{change_labels.get(field, field)}: {audit_value(event.get("old_value_json"))} → {audit_value(event.get("new_value_json"))}'
    event_rows = "".join(f'<tr><td class="audit-recorded-at">{esc(pretty_time(e.get("recorded_at")))}</td><td class="audit-recorded-by">{esc(str(e.get("recorded_by") or "System"))}</td><td class="audit-outcome">{esc(str(e.get("outcome_id") or "Profile"))}</td><td class="audit-change">{esc(audit_change(e))}</td><td class="audit-reason">{esc(str(e.get("rationale") or ""))}</td><td class="audit-evidence">{esc(str(e.get("supporting_evidence_reference") or ""))}</td></tr>' for e in events) or '<tr><td colspan="6">No events recorded.</td></tr>'
    profile_name = str(profile.get("profile_name") or "")
    status_options = [("not_selected", "Not selected"), ("included", "Included"), ("inherited", "Inherited"), ("out_of_scope", "Out of scope")]
    target_options = [("fully_implemented", "Fully implemented"), ("partly_implemented", "Partly implemented"), ("not_implemented", "Not implemented"), ("not_applicable", "Not applicable")]
    events_by_outcome: Dict[str, List[Dict[str, Any]]] = {}
    for event in events:
        event_outcome = str(event.get("outcome_id") or "").strip()
        if event_outcome:
            events_by_outcome.setdefault(event_outcome, []).append(event)
    outcome_rows_list = []
    for row in outcomes:
        outcome_id = str(row.get("outcome_id") or "")
        outcome_type = str(row.get("outcome_type") or "")
        status = str(row.get("profile_status") or "not_selected")
        status_markup = "".join(f'<option value="{value}"{" selected" if value == status else ""}>{label}</option>' for value, label in status_options)
        status_control = f'<form method="post" action="/set-csf-profile-outcome-status"><input type="hidden" name="profile_name" value="{esc(profile_name)}"><input type="hidden" name="outcome_id" value="{esc(outcome_id)}"><select name="profile_status" onchange="this.form.submit()">{status_markup}</select></form>' if editable else esc(value_labels.get(status, status))
        if editable and outcome_type == "subcategory" and status in {"included", "inherited"}:
            target = str(row.get("target_assessment_level") or "fully_implemented")
            target_markup = "".join(f'<option value="{value}"{" selected" if value == target else ""}>{label}</option>' for value, label in target_options)
            form_id = f'target-{outcome_id.lower().replace(".", "-")}'
            target_control = f'<form id="{form_id}" method="post" action="/set-csf-profile-outcome-target"><input type="hidden" name="profile_name" value="{esc(profile_name)}"><input type="hidden" name="subcategory_id" value="{esc(outcome_id)}"></form><select form="{form_id}" name="target_assessment_level">{target_markup}</select>'
            rationale_control = f'<input form="{form_id}" name="rationale" required maxlength="2000" aria-label="Reason for change for {esc(outcome_id)} Target assessment" placeholder="Why target this outcome?">'
            evidence_control = f'<input form="{form_id}" name="supporting_evidence_reference" maxlength="1000" aria-label="Supporting evidence for {esc(outcome_id)} Target assessment" placeholder="Optional record, document, or URL">'
            save_state = " is-saved" if outcome_id == saved_outcome_id else ""
            save_label = "Saved" if save_state else "Save"
            save_control = f'<button form="{form_id}" class="btn csf-profile-save{save_state}" data-profile-outcome-save type="submit">{save_label}</button>'
        else:
            target_control = '<span class="mini">Set after including</span>' if outcome_type == "subcategory" else '<span class="mini">Category rollup</span>'
            rationale_control = '<span class="mini">—</span>'
            evidence_control = '<span class="mini">Not recorded</span>'
            save_control = ''
        outcome_rows_list.append(f'<tr><td>{esc(outcome_id)}</td><td>{esc(outcome_type.title())}</td><td>{status_control}</td><td>{target_control}</td><td>{rationale_control}</td><td>{evidence_control}</td><td>{save_control}</td></tr>')
        outcome_events = events_by_outcome.get(outcome_id, [])
        if outcome_type == "subcategory" and outcome_events:
            history_items = "".join(
                f'<div class="csf-outcome-history-item"><span>{esc(pretty_time(event.get("recorded_at")))} · {esc(str(event.get("recorded_by") or "System"))}</span><strong>{esc(audit_change(event))}</strong><span>{esc(str(event.get("rationale") or ""))}</span><span>{esc(str(event.get("supporting_evidence_reference") or ""))}</span></div>'
                for event in reversed(outcome_events)
            )
            outcome_rows_list.append(f'<tr><td class="csf-outcome-history-cell" colspan="7"><div class="csf-outcome-history" aria-label="Audit history for {esc(outcome_id)}">{history_items}</div></td></tr>')
    outcome_rows = "".join(outcome_rows_list)
    delete_control = "" if not editable or profile_name == "Single-PC baseline" else f'''<form method="post" action="/archive-csf-profile"><input type="hidden" name="profile_name" value="{esc(profile_name)}"><button class="btn danger" type="submit" data-confirm-profile-delete>Delete profile</button></form>'''
    log_url = "/profile-audit?name=" + urllib.parse.quote(profile_name, safe="")
    control_catalogs = control_catalogs or []
    catalog_choices = "".join(
        f'''<label class="csf-status-choice"><input type="checkbox" name="framework_id" value="{esc(str(catalog.get("framework_id") or ""))}"{' checked' if int(catalog.get("profile_is_enabled") or 0) else ''}{' disabled' if not editable else ''}> {esc(" ".join(part for part in (str(catalog.get("display_name") or "").strip(), str(catalog.get("version") or "").strip()) if part))}</label>'''
        for catalog in control_catalogs
    ) or '<span class="mini">No control catalogs are imported in this workspace.</span>'
    catalog_summary = (
        "Select the control frameworks whose mapped controls should appear when actions are added to this Profile."
        if editable else "This frozen Profile's control catalogs are shown for reference and cannot be changed."
    )
    catalog_save = '<button class="btn" type="submit">Save control catalogs</button>' if editable else ''
    control_catalog_section = f'''<section class="csf-assessment-block"><h3>Control catalogs</h3><div class="mini">{esc(catalog_summary)}</div><form method="post" action="/set-csf-control-catalogs"><input type="hidden" name="profile_id" value="{esc(str(profile.get("profile_id") or ""))}"><input type="hidden" name="profile_name" value="{esc(profile_name)}"><div class="csf-status-options" style="margin-top:8px">{catalog_choices}</div><div class="task-actions" style="margin-top:8px">{catalog_save}</div></form></section>'''
    body = f'''<section class="panel stack"><div class="kicker">{esc(profile_label)}</div><h2>{esc(profile_name)}</h2><div class="mini">{esc(str(profile.get("context_summary") or ""))}</div><div class="mini">Community Profile source: {esc(str(profile.get("community_profile_source") or "NIST CSF 2.0 base only"))}</div>{control_catalog_section}<div class="profile-tailoring-head"><h3>Categories and Subcategories</h3><a class="btn" href="{esc(log_url)}">View log</a></div><div class="mini">{len(outcomes)} official NIST CSF records are available for tailoring. Out-of-scope and unselected outcomes are hidden from the CSF workspace.</div><table><thead><tr><th>Outcome</th><th>Type</th><th>Profile status</th><th>Target assessment</th><th>Reason</th><th>Supporting evidence</th><th></th></tr></thead><tbody>{outcome_rows}</tbody></table><div class="task-actions"><a class="btn" href="/">Back to workspace</a>{delete_control}</div></section>'''
    return render_page_shell(build_dashboard_model(config, snapshot, ""), "/profile", "Profile editor", "View this profile’s immutable creation and tailoring history.", body, show_technical_nav=persona_allows_diagnostics(config.ui_persona))


def render_profile_editor_page(
    config: AppConfig,
    snapshot: Dict[str, Any],
    profile: Dict[str, Any],
    events: List[Dict[str, Any]],
    outcomes: List[Dict[str, Any]],
    control_catalogs: Optional[List[Dict[str, Any]]] = None,
    saved_outcome_id: str = "",
) -> str:
    """Render one staged Profile-edit form so related tailoring saves together."""
    profile_kind = str(profile.get("profile_kind") or "organizational")
    editable = profile_kind == "organizational"
    profile_name = str(profile.get("profile_name") or "")
    profile_label = {"frozen_community": "Community Profile", "frozen_base": "NIST CSF Base Profile"}.get(profile_kind, "Organizational Profile")
    value_labels = {"not_selected": "Not selected", "included": "Included", "inherited": "Inherited", "out_of_scope": "Out of scope", "fully_implemented": "Fully implemented", "partly_implemented": "Partly implemented", "not_implemented": "Not implemented", "not_applicable": "Not applicable"}
    status_options = [("not_selected", "Not selected"), ("included", "Included"), ("inherited", "Inherited"), ("out_of_scope", "Out of scope")]
    target_options = [("fully_implemented", "Fully implemented"), ("partly_implemented", "Partly implemented"), ("not_implemented", "Not implemented"), ("not_applicable", "Not applicable")]

    events_by_outcome: Dict[str, List[Dict[str, Any]]] = {}
    for event in events:
        if str(event.get("outcome_id") or "").strip():
            events_by_outcome.setdefault(str(event["outcome_id"]), []).append(event)
    outcome_rows: List[str] = []
    for row in outcomes:
        outcome_id = str(row.get("outcome_id") or "")
        outcome_type = str(row.get("outcome_type") or "")
        status = str(row.get("profile_status") or "not_selected")
        status_markup = "".join(f'<option value="{value}"{" selected" if value == status else ""}>{label}</option>' for value, label in status_options)
        status_control = f'<select name="profile_status__{esc(outcome_id)}">{status_markup}</select>' if editable else esc(value_labels.get(status, status))
        if editable and outcome_type == "subcategory" and status in {"included", "inherited"}:
            target = str(row.get("target_assessment_level") or "fully_implemented")
            target_markup = "".join(f'<option value="{value}"{" selected" if value == target else ""}>{label}</option>' for value, label in target_options)
            target_control = f'<select name="target_level__{esc(outcome_id)}">{target_markup}</select>'
            rationale_control = f'<input name="rationale__{esc(outcome_id)}" required maxlength="2000" aria-label="Reason for {esc(outcome_id)} Target assessment" value="{esc(str(row.get("rationale") or ""))}" placeholder="Why target this outcome?">'
            evidence_control = f'<input name="supporting_evidence__{esc(outcome_id)}" maxlength="1000" aria-label="Supporting evidence for {esc(outcome_id)} Target assessment" value="{esc(str(row.get("supporting_evidence_reference") or ""))}" placeholder="Optional record, document, or URL">'
        else:
            target_control = '<span class="mini">Set after including</span>' if outcome_type == "subcategory" else '<span class="mini">Category rollup</span>'
            rationale_control = '<span class="mini">â€”</span>'
            evidence_control = '<span class="mini">Not recorded</span>'
        outcome_rows.append(f'<tr><td>{esc(outcome_id)}</td><td>{esc(outcome_type.title())}</td><td>{status_control}</td><td>{target_control}</td><td>{rationale_control}</td><td>{evidence_control}</td></tr>')
        history = events_by_outcome.get(outcome_id, [])
        if outcome_type == "subcategory" and history:
            history_rows = "".join(f'<div class="csf-outcome-history-item"><span>{esc(pretty_time(item.get("recorded_at")))}</span><strong>{esc(str(item.get("field_name") or item.get("event_type") or "").replace("_", " ").title())}</strong><span>{esc(str(item.get("rationale") or ""))}</span><span>{esc(str(item.get("supporting_evidence_reference") or ""))}</span></div>' for item in reversed(history))
            outcome_rows.append(f'<tr><td class="csf-outcome-history-cell" colspan="6"><div class="csf-outcome-history" aria-label="Audit history for {esc(outcome_id)}">{history_rows}</div></td></tr>')

    catalog_choices = "".join(
        f'<label class="csf-status-choice"><input type="checkbox" name="framework_id" value="{esc(str(catalog.get("framework_id") or ""))}"{" checked" if int(catalog.get("profile_is_enabled") or 0) else ""}> {esc(" ".join(part for part in (str(catalog.get("display_name") or "").strip(), str(catalog.get("version") or "").strip()) if part))}</label>'
        for catalog in (control_catalogs or [])
    ) or '<span class="mini">No control catalogs are imported in this workspace.</span>'
    saved = bool(saved_outcome_id)
    save_class = " is-saved" if saved else ""
    save_text = "Saved" if saved else "Save profile changes"
    save_disabled = " disabled" if not editable or saved else ""
    save_button = f'<button class="btn csf-profile-save csf-profile-save-all{save_class}" data-profile-save-all type="submit"{save_disabled}>{save_text}</button>' if editable else ''
    log_url = "/profile-audit?name=" + urllib.parse.quote(profile_name, safe="")
    delete_control = "" if not editable or profile_name == "Single-PC baseline" else f'<form method="post" action="/archive-csf-profile"><input type="hidden" name="profile_name" value="{esc(profile_name)}"><button class="btn danger" type="submit" data-confirm-profile-delete>Delete profile</button></form>'
    controls = f'<section class="csf-assessment-block"><h3>Control catalogs</h3><div class="mini">Select the control frameworks whose mapped controls should appear when actions are added to this Profile.</div><div class="csf-status-options" style="margin-top:8px">{catalog_choices}</div></section>' if editable else f'<section class="csf-assessment-block"><h3>Control catalogs</h3><div class="csf-status-options">{catalog_choices}</div></section>'
    body = f'''<section class="panel stack"><div class="kicker">{esc(profile_label)}</div><h2>{esc(profile_name)}</h2><div class="mini">{esc(str(profile.get("context_summary") or ""))}</div><div class="mini">Community Profile source: {esc(str(profile.get("community_profile_source") or "NIST CSF 2.0 base only"))}</div><form id="profile-edit-form" class="stack" method="post" action="/save-csf-profile-changes"><input type="hidden" name="profile_name" value="{esc(profile_name)}">{controls}<div class="profile-tailoring-head"><h3>Categories and Subcategories</h3><div class="task-actions"><a class="btn" href="{esc(log_url)}">View log</a>{save_button}</div></div><div class="mini">{len(outcomes)} official NIST CSF records are available for tailoring. Out-of-scope and unselected outcomes are hidden from the CSF workspace.</div><table><thead><tr><th>Outcome</th><th>Type</th><th>Profile status</th><th>Target assessment</th><th>Reason</th><th>Supporting evidence</th></tr></thead><tbody>{''.join(outcome_rows)}</tbody></table></form><div class="task-actions"><a class="btn" href="/">Back to workspace</a>{delete_control}</div></section>'''
    return render_page_shell(build_dashboard_model(config, snapshot, ""), "/profile", "Profile editor", "View this profileâ€™s immutable creation and tailoring history.", body, show_technical_nav=persona_allows_diagnostics(config.ui_persona))


def render_profile_audit_log_page(config: AppConfig, snapshot: Dict[str, Any], profile: Dict[str, Any], events: List[Dict[str, Any]]) -> str:
    """Render the complete immutable audit trail separately from profile tailoring."""
    value_labels = {
        "not_selected": "Not selected", "included": "Included", "inherited": "Inherited",
        "out_of_scope": "Out of scope", "fully_implemented": "Fully implemented",
        "partly_implemented": "Partly implemented", "not_implemented": "Not implemented",
        "not_applicable": "Not applicable",
    }
    field_labels = {"profile_status": "Profile status", "target_assessment_level": "Target assessment"}

    def change_text(event: Dict[str, Any]) -> str:
        field = str(event.get("field_name") or "")
        if not field:
            return str(event.get("event_type") or "").replace("_", " ").title()

        def display_value(raw: Any) -> str:
            try:
                value = json.loads(str(raw))
            except (TypeError, ValueError):
                value = raw
            if value in (None, ""):
                return "No target" if field == "target_assessment_level" else "None"
            return value_labels.get(str(value), str(value))

        return f'{field_labels.get(field, field)}: {display_value(event.get("old_value_json"))} -> {display_value(event.get("new_value_json"))}'

    rows = "".join(
        f'<tr><td class="audit-recorded-at">{esc(pretty_time(event.get("recorded_at")))}</td>'
        f'<td class="audit-recorded-by">{esc(str(event.get("recorded_by") or "System"))}</td>'
        f'<td class="audit-outcome">{esc(str(event.get("outcome_id") or "Profile"))}</td>'
        f'<td class="audit-change">{esc(change_text(event))}</td>'
        f'<td class="audit-reason">{esc(str(event.get("rationale") or ""))}</td>'
        f'<td class="audit-evidence">{esc(str(event.get("supporting_evidence_reference") or ""))}</td></tr>'
        for event in events
    ) or '<tr><td colspan="6">No events recorded.</td></tr>'
    profile_name = str(profile.get("profile_name") or "")
    back_url = "/profile?name=" + urllib.parse.quote(profile_name, safe="")
    body = f'''<section class="panel stack"><div class="kicker">Organizational Profile</div><h2>Profile audit log</h2><div class="mini">{esc(profile_name)} — immutable creation and tailoring history.</div><table class="profile-audit-log"><thead><tr><th class="audit-recorded-at" scope="col">Recorded at</th><th class="audit-recorded-by" scope="col">Recorded by</th><th class="audit-outcome" scope="col">Affected outcome</th><th class="audit-change" scope="col">Change made</th><th class="audit-reason" scope="col">Reason</th><th class="audit-evidence" scope="col">Supporting evidence</th></tr></thead><tbody>{rows}</tbody></table><div class="task-actions"><a class="btn" href="{esc(back_url)}">Back to profile</a></div></section>'''
    return render_page_shell(build_dashboard_model(config, snapshot, ""), "/profile-audit", "Profile audit log", "Review the chronological, append-only profile history.", body, show_technical_nav=persona_allows_diagnostics(config.ui_persona))


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
    return render_page_shell(model, "/govern", "Govern", simplify_for_home(persona_id, "Review task health and the operating decisions that determine how this PC is monitored.", "Check that monitoring is running well and review the choices that guide it."), body, show_technical_nav=True)


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
    return render_page_shell(model, "/identify", "Identify", simplify_for_home(persona_id, "Confirm the baseline scope, watched assets, and local environment reflected in the evidence below.", "Check what this PC includes and what the app is watching."), body, show_technical_nav=True)


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
    return render_page_shell(model, "/protect", "Protect", simplify_for_home(persona_id, "Review protection controls needing attention and the profile they are evaluated against.", "Review the protections this PC should have and what needs care."), body, show_technical_nav=True)


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
    return render_page_shell(model, "/detect", "Detect", simplify_for_home(persona_id, "Review current intelligence, host evidence, and monitoring health to decide what merits investigation.", "Review what the app found and whether anything needs a closer look."), body, show_technical_nav=True)


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


def render_respond_summary_cards(cards: List[Dict[str, Any]]) -> str:
    return "".join(render_metric(card.get("label") or "", card.get("value") or 0, card.get("tone") or "") for card in cards)


def render_respond_finding_card(finding: Dict[str, Any], persona_profile: Dict[str, Any]) -> str:
    persona_id = str(persona_profile.get("persona_id") or "user")
    evidence_rows = "".join(f"<tr><td>{esc(item['label'])}</td><td>{esc(item['value'])}</td></tr>" for item in finding.get("evidence") or [])
    if not evidence_rows:
        evidence_rows = "<tr><td colspan='2' class='mini'>Not available.</td></tr>"
    rule_detail = ""
    if finding.get("matched_rule_id") or finding.get("matched_rule_description"):
        rule_detail = f'<div class="mini"><strong>Matched rule:</strong> {esc(finding.get("matched_rule_id") or "Unknown")} {esc(finding.get("matched_rule_description") or "")}</div>'
    guardrail_detail = ""
    if finding.get("guardrail_matched"):
        reason = finding.get("accepted_blocked_reason") or finding.get("guardrail_reason") or "This finding cannot be accepted as routine because it affects a protected security condition."
        guardrail_detail = f'<div class="finding high">Acceptance blocked: {esc(reason)}</div>'
    accepted_detail = ""
    if finding.get("is_accepted"):
        accepted_detail = f'<div class="finding">Accepted posture change: {esc(finding.get("accepted_reason") or "This exact change was reviewed and recorded locally. It remains in the audit trail.")}</div>'
    accept_detail = ""
    if finding.get("acceptance_allowed"):
        if persona_id in ("advanced_user", "analyst", "tech"):
            accept_detail = f'<details class="inline-detail mini"><summary>Accept exact reviewed change</summary><div class="detail-body">Use the existing helper after review. This records an exact accepted posture change locally and does not suppress future unrelated findings.</div><pre>{esc(finding.get("accept_helper_command") or "")}</pre></details>'
        elif persona_id == "csf_native":
            accept_detail = '<details class="inline-detail mini"><summary>Accept exact reviewed change</summary><div class="detail-body">This is an auditable governance action. Switch to Advanced User, Analyst, or Technician mode to use the exact acceptance helper command.</div></details>'
        else:
            accept_detail = '<div class="mini">This is an advanced review action. Switch to Advanced User or Technician mode to accept an exact reviewed change.</div>'
    source_line = f'<div class="mini">Source: <a href="{esc(finding.get("report_href") or "/reports")}">{esc(finding.get("report_name") or "latest posture report")}</a></div>'
    if persona_id == "tech":
        source_line += f'<div class="path" style="margin-top:8px">{esc(finding.get("report_path") or "")}</div>'
        source_line += f'<div class="mini" style="margin-top:8px">Finding index: {esc(finding.get("index"))}</div>'
    actions = [
        '<span class="btn">Review evidence</span>',
        '<span class="btn">Investigate</span>',
    ]
    if finding.get("guardrail_matched") or lower_text(finding.get("severity")) in ("warning", "critical"):
        actions.extend(['<span class="btn">Mitigate</span>', '<span class="btn">Escalate</span>'])
    if finding.get("acceptance_allowed"):
        actions.append('<span class="btn">Accept exact reviewed change</span>')
    actions.extend([
        '<span class="btn">Leave open</span>',
        f'<a class="btn" href="{esc(finding.get("report_href") or "/reports")}">Export evidence</a>',
        '<a class="btn" href="/recover">Validate in Recover</a>',
    ])
    return f"""
<div class="task">
  <div class="task-head">
    <div>
      <div class="task-name">{esc(finding.get('title'))}</div>
      <div class="task-meta">{esc(finding.get('section'))} | {esc(finding.get('item_type'))}</div>
      <div style="margin-top:10px">{render_status_badge(finding.get('status_label'), finding.get('tone'))} <span class="mini" style="margin-left:8px">Severity: {esc(finding.get('severity'))} | Classification: {esc(finding.get('classification'))}</span></div>
    </div>
  </div>
  {guardrail_detail}
  {accepted_detail}
  <div class="stack">
    <div><strong>What changed</strong><div class="mini">{esc(finding.get('what_changed'))}</div></div>
    <div><strong>Why it matters</strong><div class="mini">{esc(finding.get('why_it_matters'))}</div></div>
    <div><strong>Recommended response</strong><div class="mini">{esc(finding.get('recommended_response'))}</div></div>
    <div><strong>CSF mapping</strong><div class="mini">{esc(finding.get('csf_mapping'))}</div></div>
    {rule_detail}
    {source_line}
    <details class="task-detail"><summary>Evidence</summary><table><tbody>{evidence_rows}</tbody></table></details>
    <details class="task-detail"><summary>Mitigation guidance</summary><div class="mini">{esc(mitigation_guidance(finding.get('source_change') or {}, persona_id))}</div></details>
    {accept_detail}
    <div class="task-actions">{''.join(actions)}</div>
  </div>
</div>
"""


def render_recorded_change_card(finding: Dict[str, Any]) -> str:
    badge = render_status_badge(finding.get("status_label"), "ok")
    return f"""
<div class="care-tile good">
  <h4>{esc(finding.get('title'))}</h4>
  <div style="margin-bottom:8px">{badge}</div>
  <p>{esc(finding.get('why_it_matters'))}</p>
  <div class="mini" style="margin-top:8px"><a href="{esc(finding.get('report_href') or '/reports')}">Open source report</a></div>
</div>
"""


def render_respond_page(config: AppConfig, snapshot: Dict[str, Any], message: str = "") -> str:
    model = build_dashboard_model(config, snapshot, message)
    persona_id = config.ui_persona
    persona_profile = model["app"]["persona_profile"]
    respond = model["csf_sections"]["respond"]
    tasks_by_name = model["task_job_health"]["by_name"]
    notifier_task = tasks_by_name.get("Codex Alert Notifier", {})
    notifier_status = classify_task_result(notifier_task) if notifier_task else {"label": "Unknown", "tone": "medium", "message": "Alert delivery state is unavailable."}
    pending_rows = "".join(render_alert_row(item, lifecycle_state=str(item.get("lifecycle_state") or "pending").title(), show_actions=True) for item in model["alerts"]["pending"][:20]) or "<tr><td colspan='5' class='mini'>No pending alerts.</td></tr>"
    archive_rows = "".join(render_alert_row(item, lifecycle_state=str(item.get("lifecycle_state") or "recorded").title(), show_actions=False) for item in model["alerts"]["archived"][:20]) or "<tr><td colspan='5' class='mini'>No recorded alerts.</td></tr>"
    triage_steps = "".join(f"<li>{esc(step)}</li>" for step in respond["triage_steps"])
    lifecycle_rows = "".join(f"<tr><td>{render_status_badge(item['state'], 'info' if item['state'] != 'Archived' else 'ok')}</td><td>{esc(item['meaning'])}</td></tr>" for item in respond["lifecycle"])
    active_cards = "".join(render_respond_finding_card(item, persona_profile) for item in respond.get("active_findings") or [])
    recorded_cards = "".join(render_recorded_change_card(item) for item in respond.get("recorded_findings") or [])
    latest_report_line = ""
    if respond.get("latest_report_name"):
        latest_report_line = f'<div class="mini">Latest posture report: <a href="{esc(respond.get("latest_report_href") or "/reports")}">{esc(respond.get("latest_report_name"))}</a> | {esc(pretty_time(respond.get("latest_report_time") or ""))}</div>'
    if persona_id == "user":
        lede = "Review the response queue and decide whether any current finding needs follow-through."
    elif persona_id == "csf_native":
        lede = "Review the current response queue, document any required decision, and retain the linked evidence."
    else:
        lede = "Review current findings, determine their significance, and document any required response action."
    if respond.get("queue_state") == "missing_report":
        queue_markup = '<div class="finding">No posture check report is available yet. Run a posture check from Detect.</div><div class="task-actions"><a class="btn" href="/detect">Open Detect</a></div>'
    elif respond.get("queue_state") == "report_error":
        queue_markup = f'<div class="finding high">{esc(respond.get("queue_message") or "Latest posture report could not be parsed.")}</div>'
    elif active_cards:
        queue_markup = active_cards
    else:
        queue_markup = f'<div class="finding">{esc(respond.get("queue_message") or "No findings currently require response.")}</div>'
    recorded_section = ""
    if recorded_cards:
        recorded_section = f'<section class="panel stack" style="margin-top:18px"><div class="kicker">Respond</div><h2>Recorded but no response required</h2><div class="mini">These changes remain in the audit trail, but they are not active response items.</div><div class="grid two">{recorded_cards}</div></section>'
    body = f"""
<section class="panel stack" style="margin-top:18px">
  <div class="kicker">Respond</div>
  <h2>Respond to findings</h2>
  <div class="mini">{esc(respond.get('queue_message') or respond.get('summary') or '')}</div>
  {latest_report_line}
  <div class="mini">Notifier status: {render_status_badge(notifier_status['label'], notifier_status['tone'])} <span style="margin-left:8px">{esc(notifier_status['message'])}</span></div>
  <div class="cards">{render_respond_summary_cards(respond.get('summary_cards') or [])}</div>
</section>
<section class="panel stack" style="margin-top:18px">
  <div class="kicker">Respond</div>
  <h2>Findings to handle</h2>
  {queue_markup}
</section>
{recorded_section}
<section class="grid two" style="margin-top:18px">
  <div class="panel stack">
    <div class="kicker">Respond</div>
    <h2>Suggested triage</h2>
    <div class="focus-card report"><div class="focus-copy"><ul style="margin:0; padding-left:18px;">{triage_steps}</ul></div></div>
    <div class="mini">After response actions are taken, use Recover to confirm confidentiality, integrity, and availability are restored.</div>
  </div>
  <div class="panel stack">
    <div class="kicker">Respond</div>
    <h2>Alert lifecycle</h2>
    <div class="mini">Pending alerts are treated as New. Archived alerts are treated as Archived until backend workflow state is implemented.</div>
    <table><thead><tr><th>State</th><th>Meaning</th></tr></thead><tbody>{lifecycle_rows}</tbody></table>
  </div>
</section>
<section class="grid two" style="margin-top:18px">
  <div class="panel stack">
    <div class="kicker">Respond</div>
    <h2>Pending Alerts</h2>
    <table><thead><tr><th>Severity</th><th>Alert</th><th>State</th><th>Finding ID</th><th>Collected</th></tr></thead><tbody>{pending_rows}</tbody></table>
  </div>
  <div class="panel stack">
    <div class="kicker">Respond</div>
    <h2>Recorded Alerts</h2>
    <table><thead><tr><th>Severity</th><th>Alert</th><th>State</th><th>Finding ID</th><th>Collected</th></tr></thead><tbody>{archive_rows}</tbody></table>
  </div>
</section>
"""
    return render_page_shell(model, "/respond", "Respond to findings", lede, body, show_technical_nav=True)


def render_recover_page(config: AppConfig, snapshot: Dict[str, Any], message: str = "") -> str:
    model = build_dashboard_model(config, snapshot, message)
    persona_id = config.ui_persona
    recovery = model["recovery_readiness"]
    recovery_rows = "".join(f"<tr><td>{esc(label)}</td><td>{esc(entry['Status'])}</td><td>{esc(pretty_time(entry['Value']) if 'Baseline' in label else entry['Value'])}</td><td>{esc(entry['Message'])}</td></tr>" for label, entry in [("Last known-good baseline", recovery["LastKnownGoodBaseline"]), ("Rollback records status", recovery["RollbackRecords"]), ("Restore point status", recovery["RestorePointStatus"]), ("Backup status", recovery["BackupStatus"]), ("Post-remediation validation", recovery["PostRemediationValidation"])])
    recovery_recommendations = "".join(f"<li>{esc(item)}</li>" for item in recovery["Recommendations"])
    return render_page_shell(model, "/recover", "Recover", simplify_for_home(persona_id, "Review baseline, rollback, backup, and validation readiness before closing a change or recovery action.", "Check that this PC has what it needs to return to steady."), render_recovery_card(recovery, recovery_rows, recovery_recommendations), show_technical_nav=True)


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
    server_version = f"CodexMonitorUI/{UI_DISPLAY_VERSION}"

    @property
    def app_config(self) -> AppConfig:
        return self.server.app_config  # type: ignore[attr-defined]

    def respond_ui_page(self, document: str, fragment: str) -> None:
        self.respond_html(extract_csf_app_fragment(document) if fragment == "app" else document)

    def get_ui_snapshot(
        self,
        route: str,
        *,
        force_live: bool = False,
        explorer_selection: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        lock = getattr(self.server, "snapshot_lock", None)
        if lock is None:
            lock = threading.Lock()
            self.server.snapshot_lock = lock  # type: ignore[attr-defined]
        with lock:
            cached = getattr(self.server, "ui_snapshot_cache", None)
            if force_live or cached is None:
                cached = build_snapshot(self.app_config)
                self.server.ui_snapshot_cache = cached  # type: ignore[attr-defined]
        if route in {"/", "/detect", "/detect/evidence-snapshot", "/respond", "/recover", "/reports"}:
            snapshot = refresh_sqlite_backed_snapshot(self.app_config, cached)
        else:
            snapshot = copy.deepcopy(cached)
        snapshot["csf_subcategory_guidance"] = list_sqlite_csf_guidance(self.app_config.state_db_path)
        snapshot["csf_subcategory_product_examples"] = list_sqlite_csf_product_examples(self.app_config.state_db_path)
        snapshot["csf_subcategory_profile_metadata"] = list_sqlite_csf_profile_metadata(self.app_config.state_db_path)
        snapshot["csf_profile_context"] = get_sqlite_csf_profile_context(self.app_config.state_db_path)
        active_profile_id = str(((snapshot.get("csf_profile_context") or {}).get("active_profile") or {}).get("profile_id") or "")
        active_profile_name = str(((snapshot.get("csf_profile_context") or {}).get("active_profile") or {}).get("profile_name") or "")
        snapshot["csf_profile_scope"] = list_sqlite_csf_profile_scope(self.app_config.state_db_path, active_profile_name)
        snapshot["csf_community_profile_guidance"] = list_sqlite_csf_community_profile_guidance(self.app_config.state_db_path, active_profile_id)
        snapshot["csf_current_assessments"] = list_sqlite_csf_current_assessments(self.app_config.state_db_path, active_profile_id) if active_profile_id else {}
        profile_targets = list_sqlite_csf_profile_targets(self.app_config.state_db_path, active_profile_id) if active_profile_id else {}
        for target in profile_targets.values():
            target["profile_name"] = active_profile_name
        snapshot["csf_profile_assessments"] = profile_targets
        snapshot["csf_state_db_path"] = str(self.app_config.state_db_path)
        selected_subcategory_id = str((explorer_selection or {}).get("subcategory_id") or "")
        snapshot["csf_outcome_records"] = list_sqlite_csf_outcome_records(
            self.app_config.state_db_path, active_profile_id, selected_subcategory_id
        )
        snapshot["csf_information_flow"] = get_sqlite_csf_information_flow(
            self.app_config.state_db_path, selected_subcategory_id
        )
        snapshot["csf_explorer_selection"] = dict(explorer_selection or {})
        return snapshot

    def do_GET(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        params = urllib.parse.parse_qs(parsed.query)
        fragment = params.get("fragment", [""])[0].strip().lower()
        force_live = params.get("refresh", [""])[0].strip().lower() == "live"
        explorer_selection = {
            "category_id": params.get("csf_category", [""])[0],
            "subcategory_id": params.get("csf_subcategory", [""])[0],
        }

        if self.app_config.app_mode == "analyst" and parsed.path in {
            "/alert", "/report", "/reports", "/diagnostics", "/detect/evidence-snapshot",
        }:
            return self.respond_error(
                HTTPStatus.NOT_FOUND,
                "Scanning, alerting, and monitor reports are available in the Codex Monitor app, not CSF Analyst.",
            )

        try:
            if parsed.path == "/":
                message = params.get("message", [""])[0]
                snapshot = self.get_ui_snapshot(parsed.path, force_live=force_live, explorer_selection=explorer_selection)
                return self.respond_ui_page(render_dashboard(self.app_config, snapshot, message), fragment)

            if parsed.path == "/govern":
                message = params.get("message", [""])[0]
                snapshot = self.get_ui_snapshot(parsed.path, force_live=force_live, explorer_selection=explorer_selection)
                return self.respond_ui_page(render_govern_page(self.app_config, snapshot, message), fragment)

            if parsed.path == "/identify":
                message = params.get("message", [""])[0]
                snapshot = self.get_ui_snapshot(parsed.path, force_live=force_live, explorer_selection=explorer_selection)
                return self.respond_ui_page(render_identify_page(self.app_config, snapshot, message), fragment)

            if parsed.path == "/protect":
                message = params.get("message", [""])[0]
                snapshot = self.get_ui_snapshot(parsed.path, force_live=force_live, explorer_selection=explorer_selection)
                return self.respond_ui_page(render_protect_page(self.app_config, snapshot, message), fragment)

            if parsed.path == "/detect":
                message = params.get("message", [""])[0]
                snapshot = self.get_ui_snapshot(parsed.path, force_live=force_live, explorer_selection=explorer_selection)
                return self.respond_ui_page(render_detect_page(self.app_config, snapshot, message), fragment)

            if parsed.path == "/detect/evidence-snapshot":
                message = params.get("message", [""])[0]
                snapshot = self.get_ui_snapshot(parsed.path, force_live=force_live, explorer_selection=explorer_selection)
                return self.respond_ui_page(render_detect_evidence_snapshot_page(self.app_config, snapshot, message), fragment)

            if parsed.path == "/respond":
                message = params.get("message", [""])[0]
                snapshot = self.get_ui_snapshot(parsed.path, force_live=force_live, explorer_selection=explorer_selection)
                return self.respond_ui_page(render_respond_page(self.app_config, snapshot, message), fragment)

            if parsed.path == "/recover":
                message = params.get("message", [""])[0]
                snapshot = self.get_ui_snapshot(parsed.path, force_live=force_live, explorer_selection=explorer_selection)
                return self.respond_ui_page(render_recover_page(self.app_config, snapshot, message), fragment)

            if parsed.path == "/reports":
                message = params.get("message", [""])[0]
                snapshot = self.get_ui_snapshot(parsed.path, force_live=force_live)
                return self.respond_ui_page(render_reports_page(self.app_config, snapshot, message), fragment)

            if parsed.path == "/diagnostics":
                message = params.get("message", [""])[0]
                snapshot = self.get_ui_snapshot(parsed.path, force_live=force_live)
                return self.respond_ui_page(render_diagnostics_page(self.app_config, snapshot, message), fragment)

            if parsed.path == "/control-catalogs":
                message = params.get("message", [""])[0]
                snapshot = self.get_ui_snapshot(parsed.path, force_live=force_live)
                return self.respond_ui_page(render_control_catalogs_page(self.app_config, snapshot, message), fragment)

            if parsed.path == "/evidence":
                message = params.get("message", [""])[0]
                snapshot = self.get_ui_snapshot(parsed.path, force_live=force_live)
                return self.respond_ui_page(render_evidence_library_page(self.app_config, snapshot, message, params.get("basis_id", [""])[0]), fragment)

            if parsed.path == "/audit-log":
                snapshot = self.get_ui_snapshot(parsed.path, force_live=force_live)
                return self.respond_ui_page(
                    render_audit_log_page(self.app_config, snapshot, params.get("log", ["all"])[0]),
                    fragment,
                )

            if parsed.path == "/community-profiles":
                message = params.get("message", [""])[0]
                snapshot = self.get_ui_snapshot(parsed.path, force_live=force_live)
                return self.respond_ui_page(render_community_profiles_page(self.app_config, snapshot, message), fragment)

            if parsed.path == "/profile-creation":
                snapshot = self.get_ui_snapshot(parsed.path, force_live=force_live)
                return self.respond_ui_page(render_profile_creation_page(self.app_config, snapshot), fragment)

            if parsed.path == "/profile":
                profile_name = params.get("name", [""])[0].strip()
                connection = ioc_store.connect_db(self.app_config.state_db_path)
                try:
                    ioc_store.init_db(connection)
                    profile = next((row for row in ioc_store.list_csf_profile_definitions(connection) if row["profile_name"] == profile_name), None)
                    if profile is None:
                        return self.respond_error(HTTPStatus.NOT_FOUND, "Profile not found.")
                    events = ioc_store.list_csf_profile_audit_events(connection, profile_name)
                    outcomes = ioc_store.list_csf_profile_outcomes(connection, profile_name)
                    catalogs = ioc_store.list_csf_profile_control_catalogs(connection, profile.get("profile_id"))
                finally:
                    connection.close()
                snapshot = self.get_ui_snapshot(parsed.path, force_live=force_live)
                return self.respond_ui_page(
                    render_profile_editor_page(
                        self.app_config, snapshot, profile, events, outcomes, catalogs,
                        params.get("saved", params.get("saved_outcome", [""]))[0].strip().upper(),
                    ),
                    fragment,
                )

            if parsed.path == "/profile-audit":
                profile_name = params.get("name", [""])[0].strip()
                connection = ioc_store.connect_db(self.app_config.state_db_path)
                try:
                    ioc_store.init_db(connection)
                    profile = next((row for row in ioc_store.list_csf_profile_definitions(connection) if row["profile_name"] == profile_name), None)
                    if profile is None:
                        return self.respond_error(HTTPStatus.NOT_FOUND, "Profile not found.")
                    events = ioc_store.list_csf_profile_audit_events(connection, profile_name)
                finally:
                    connection.close()
                snapshot = self.get_ui_snapshot(parsed.path, force_live=force_live)
                return self.respond_ui_page(render_profile_audit_log_page(self.app_config, snapshot, profile, events), fragment)

            if parsed.path == "/csf-profiles":
                snapshot = self.get_ui_snapshot(parsed.path, force_live=force_live)
                modal = render_csf_profiles_modal(snapshot.get("csf_profile_context") or {}, "/")
                if fragment == "modal":
                    return self.respond_html(modal)
                return self.respond_html(html_page("CSF Profiles", modal))

            if parsed.path == "/csf-profile" and params.get("new", [""])[0] == "1":
                snapshot = self.get_ui_snapshot(parsed.path, force_live=force_live)
                modal = render_new_csf_profile_modal(
                    (snapshot.get("csf_profile_context") or {}).get("community_profiles") or [], "/"
                )
                if fragment == "modal":
                    return self.respond_html(modal)
                return self.respond_html(html_page("New CSF Profile", modal))

            if parsed.path == "/alert":
                alert_id = params.get("id", [""])[0]
                detail = get_sqlite_alert_detail(self.app_config.state_db_path, alert_id)
                if not detail.get("found"):
                    return self.respond_error(HTTPStatus.NOT_FOUND, "SQLite alert not found.")
                alert_title = str(detail["alert"].get("alert_id") or "SQLite alert")
                alert_subtitle = "SQLite alert record; use export-alert with this immutable ID for a JSON export."
                alert_payload = json.dumps(detail, indent=2)
                if fragment == "modal":
                    return self.respond_html(render_record_modal(alert_title, render_record_payload(alert_title, alert_subtitle, alert_payload), parsed.path + ("?" + parsed.query.replace("fragment=modal", "").strip("&") if parsed.query else "")))
                return self.respond_html(render_file_detail(
                    alert_title,
                    alert_subtitle,
                    alert_payload,
                ))

            if parsed.path == "/report":
                report_id = params.get("id", [""])[0]
                if report_id:
                    detail = resolve_inactive_sqlite_report_route(self.app_config.state_db_path, report_id)
                    if not detail.get("found"):
                        return self.respond_error(HTTPStatus.NOT_FOUND, "SQLite report not found.")
                    if fragment == "modal":
                        report_title = str((detail.get("report") or {}).get("report_id") or "SQLite report")
                        return self.respond_html(render_record_modal(report_title, render_sqlite_report_detail_preview(detail), build_sqlite_report_href(report_id)))
                    return self.respond_html(render_sqlite_report_detail_preview(detail))
                requested = params.get("path", [""])[0]
                roots = [self.app_config.runtime_root, self.app_config.data_root, self.app_config.repo_root]
                report_path = safe_path(requested, roots)
                if report_path is None or not report_path.exists():
                    return self.respond_error(HTTPStatus.NOT_FOUND, "Report file not found.")
                if report_path.suffix.lower() == ".json":
                    payload_text = json.dumps(parse_json(report_path), indent=2)
                else:
                    payload_text = read_text(report_path)
                if fragment == "modal":
                    detail_href = "/report?path=" + urllib.parse.quote(requested, safe="")
                    return self.respond_html(render_record_modal(report_path.name, render_record_payload(report_path.name, str(report_path), payload_text), detail_href))
                return self.respond_html(render_file_detail(report_path.name, str(report_path), payload_text))

            if parsed.path in {"/csf-reviewed-action", "/csf-supporting-basis"}:
                subcategory_id = params.get("csf_subcategory", [""])[0].strip().upper()
                category_id = params.get("csf_category", [""])[0].strip().upper()
                official_subcategory = csf_catalog.find_official_subcategory(subcategory_id)
                if official_subcategory is None or category_id != str(official_subcategory.get("category_id") or ""):
                    return self.respond_error(HTTPStatus.BAD_REQUEST, "Choose an official CSF Subcategory before adding a record.")
                profile_context = get_sqlite_csf_profile_context(self.app_config.state_db_path)
                active_profile = profile_context.get("active_profile") or {}
                active_profile_id = str(active_profile.get("profile_id") or "")
                if not active_profile_id:
                    return self.respond_error(HTTPStatus.BAD_REQUEST, "Choose an Organizational Profile before adding a Tile 3 record.")
                records = list_sqlite_csf_outcome_records(self.app_config.state_db_path, active_profile_id, subcategory_id)
                profile_assessment = list_sqlite_csf_profile_targets(
                    self.app_config.state_db_path, active_profile_id
                ).get(subcategory_id, {})
                is_action = parsed.path == "/csf-reviewed-action"
                record_id = params.get("action_id" if is_action else "basis_id", [""])[0].strip()
                if not record_id and str(active_profile.get("profile_kind") or "organizational") != "organizational":
                    return self.respond_error(HTTPStatus.FORBIDDEN, "Frozen base and Community Profiles are read-only. Create or select an Organizational Profile to add actions or evidence.")
                record = next((row for row in records["reviewed_actions" if is_action else "supporting_basis"] if str(row.get("action_id" if is_action else "basis_id")) == record_id), None)
                action_updates: List[Dict[str, Any]] = []
                evidence_link_events: List[Dict[str, Any]] = []
                if is_action and record is not None:
                    connection = ioc_store.connect_db(self.app_config.state_db_path)
                    try:
                        action_updates = ioc_store.list_csf_reviewed_action_updates(connection, record_id)
                        evidence_link_events = ioc_store.list_csf_evidence_link_audit_events(
                            connection, active_profile_id, target_type="action", target_id=record_id
                        )
                    finally:
                        connection.close()
                generic_examples = list_sqlite_csf_generic_action_examples(
                    self.app_config.state_db_path
                ).get(subcategory_id, {})
                profile_examples = list_sqlite_csf_profile_action_examples(
                    self.app_config.state_db_path, active_profile_id
                ).get(subcategory_id, {})
                sample_opportunity = list_sqlite_csf_profile_sample_opportunities(
                    self.app_config.state_db_path, active_profile_id
                ).get(subcategory_id, {})
                modal = render_csf_entry_modal(
                    is_action and "action" or "basis",
                    subcategory_id,
                    category_id,
                    params.get("return_to", ["/"])[0] or "/",
                    record,
                    action_updates,
                    params.get("edit", [""])[0].strip() == "1",
                    list(records.get("mapped_controls") or []),
                    list(records.get("evidence_library") or []),
                    str(official_subcategory.get("outcome") or ""),
                    profile_assessment,
                    merged_action_examples(generic_examples, profile_examples),
                    int(records.get("enabled_control_catalog_count") or 0),
                    sample_opportunity,
                    evidence_link_events,
                )
                if fragment == "modal":
                    return self.respond_html(modal)
                return self.respond_html(html_page("CSF Tile 3", modal))

            if parsed.path == "/api/snapshot":
                return self.respond_json(self.get_ui_snapshot(parsed.path, force_live=force_live))

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
            query_params = urllib.parse.parse_qs(parsed.query)
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
                "/control-catalogs",
                "/evidence",
                "/audit-log",
                "/profile",
            }
            if return_to not in allowed_return_routes:
                return_to = "/"

            if self.app_config.app_mode == "analyst" and parsed.path in {
                "/run-task", "/run-tripwire-baseline", "/set-protection-profile", "/set-ui-persona",
            }:
                return self.respond_error(
                    HTTPStatus.NOT_FOUND,
                    "Scanning, alerting, and monitor automation are available in the Codex Monitor app, not CSF Analyst.",
                )

            if parsed.path == "/run-task":
                task_name = payload.get("task_name", [""])[0]
                if task_name not in TASK_NAMES:
                    raise RuntimeError("Unknown task requested.")
                result = run_task(task_name, self.app_config)
                return self.redirect(return_to + "?message=" + urllib.parse.quote(result))

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

            if parsed.path == "/set-active-csf-profile":
                profile_name = payload.get("profile_name", [""])[0].strip()
                connection = ioc_store.connect_db(self.app_config.state_db_path)
                try:
                    ioc_store.init_db(connection)
                    ioc_store.set_active_csf_profile(connection, profile_name)
                finally:
                    connection.close()
                if return_to == "/profile":
                    return self.redirect(
                        "/profile?" + urllib.parse.urlencode({
                            "name": profile_name,
                            "message": f"Active profile: {profile_name}",
                        })
                    )
                return self.redirect(return_to + "?message=" + urllib.parse.quote(f"Active profile: {profile_name}"))

            if parsed.path == "/archive-csf-profile":
                profile_name = payload.get("profile_name", [""])[0].strip()
                connection = ioc_store.connect_db(self.app_config.state_db_path)
                try:
                    ioc_store.init_db(connection)
                    ioc_store.archive_csf_profile_definition(connection, profile_name, getpass.getuser())
                finally:
                    connection.close()
                return self.redirect("/?message=" + urllib.parse.quote(f"Deleted profile: {profile_name}"))

            if parsed.path == "/save-csf-profile-changes":
                profile_name = payload.get("profile_name", [""])[0].strip()
                if not profile_name:
                    raise RuntimeError("Profile name is required.")
                selected_frameworks = {str(value or "").strip() for value in payload.get("framework_id", []) if str(value or "").strip()}
                connection = ioc_store.connect_db(self.app_config.state_db_path)
                try:
                    ioc_store.init_db(connection)
                    definition = next((item for item in ioc_store.list_csf_profile_definitions(connection) if str(item.get("profile_name") or "") == profile_name), None)
                    if definition is None or str(definition.get("profile_kind") or "") != "organizational":
                        raise RuntimeError("Only an Organizational Profile can be edited.")
                    original_outcomes = ioc_store.list_csf_profile_outcomes(connection, profile_name)
                    for outcome in original_outcomes:
                        outcome_id = str(outcome.get("outcome_id") or "")
                        requested_status = payload.get(f"profile_status__{outcome_id}", [""])[0].strip()
                        if requested_status and requested_status != str(outcome.get("profile_status") or "not_selected"):
                            ioc_store.set_csf_profile_outcome_status(connection, profile_name, outcome_id, requested_status, getpass.getuser())
                    current_outcomes = {str(item.get("outcome_id") or ""): item for item in ioc_store.list_csf_profile_outcomes(connection, profile_name)}
                    for outcome_id, outcome in current_outcomes.items():
                        if str(outcome.get("outcome_type") or "") != "subcategory":
                            continue
                        requested_level = payload.get(f"target_level__{outcome_id}", [""])[0].strip()
                        if not requested_level or str(outcome.get("profile_status") or "") not in {"included", "inherited"}:
                            continue
                        requested_reason = payload.get(f"rationale__{outcome_id}", [""])[0]
                        requested_evidence = payload.get(f"supporting_evidence__{outcome_id}", [""])[0]
                        if (
                            requested_level != str(outcome.get("target_assessment_level") or "fully_implemented")
                            or requested_reason != str(outcome.get("rationale") or "")
                            or requested_evidence != str(outcome.get("supporting_evidence_reference") or "")
                        ):
                            ioc_store.set_csf_profile_outcome_target(
                                connection, profile_name, outcome_id, requested_level, requested_reason,
                                getpass.getuser(), requested_evidence,
                            )
                    profile_id = str(definition.get("profile_id") or "")
                    catalogs = ioc_store.list_csf_profile_control_catalogs(connection, profile_id)
                    registered_frameworks = {str(catalog["framework_id"]) for catalog in catalogs}
                    unknown_frameworks = selected_frameworks - registered_frameworks
                    if unknown_frameworks:
                        raise RuntimeError("The selected control catalog is not registered.")
                    previous_frameworks = sorted(str(catalog["framework_id"]) for catalog in catalogs if int(catalog.get("profile_is_enabled") or 0))
                    if previous_frameworks != sorted(selected_frameworks):
                        for framework_id in registered_frameworks:
                            ioc_store.set_csf_profile_control_catalog_enabled(connection, profile_id, framework_id, framework_id in selected_frameworks, getpass.getuser())
                        ioc_store.record_csf_profile_audit_event(
                            connection, profile_name=profile_name, event_type="profile_updated", field_name="control_catalogs",
                            old_value=previous_frameworks, new_value=sorted(selected_frameworks),
                            rationale="Control catalog selection changed.", recorded_by=getpass.getuser(),
                        )
                finally:
                    connection.close()
                return self.redirect("/profile?name=" + urllib.parse.quote(profile_name, safe="") + "&saved=1")

            if parsed.path == "/set-csf-profile-outcome-status":
                profile_name = payload.get("profile_name", [""])[0].strip()
                outcome_id = payload.get("outcome_id", [""])[0].strip()
                profile_status = payload.get("profile_status", [""])[0].strip()
                connection = ioc_store.connect_db(self.app_config.state_db_path)
                try:
                    ioc_store.init_db(connection)
                    ioc_store.set_csf_profile_outcome_status(connection, profile_name, outcome_id, profile_status, getpass.getuser())
                finally:
                    connection.close()
                return self.redirect("/profile?name=" + urllib.parse.quote(profile_name, safe=""))

            if parsed.path == "/set-csf-profile-outcome-target":
                profile_name = payload.get("profile_name", [""])[0].strip()
                subcategory_id = payload.get("subcategory_id", [""])[0].strip().upper()
                target_level = payload.get("target_assessment_level", [""])[0].strip()
                rationale = payload.get("rationale", [""])[0]
                supporting_evidence_reference = payload.get("supporting_evidence_reference", [""])[0]
                connection = ioc_store.connect_db(self.app_config.state_db_path)
                try:
                    ioc_store.init_db(connection)
                    ioc_store.set_csf_profile_outcome_target(connection, profile_name, subcategory_id, target_level, rationale, getpass.getuser(), supporting_evidence_reference)
                finally:
                    connection.close()
                return self.redirect(
                    "/profile?name=" + urllib.parse.quote(profile_name, safe="")
                    + "&saved_outcome=" + urllib.parse.quote(subcategory_id, safe="")
                )

            if parsed.path == "/create-csf-profile":
                profile_name = payload.get("profile_name", [""])[0]
                context_summary = payload.get("context_summary", [""])[0]
                community_profile_id = payload.get("community_profile_id", [""])[0]
                source_profile_id = payload.get("source_profile_id", [""])[0]
                control_framework_ids = payload.get("framework_id", [])
                connection = ioc_store.connect_db(self.app_config.state_db_path)
                try:
                    ioc_store.init_db(connection)
                    profile = ioc_store.create_csf_profile_definition(
                        connection, profile_name, context_summary, community_profile_id=community_profile_id,
                        source_profile_id=source_profile_id,
                        control_framework_ids=control_framework_ids,
                        recorded_by=getpass.getuser(),
                    )
                finally:
                    connection.close()
                return self.redirect(
                    "/profile?name=" + urllib.parse.quote(str(profile["profile_name"]), safe="")
                    + "&message=" + urllib.parse.quote("Tailor included outcomes and Target assessments.")
                )

            if parsed.path == "/set-csf-control-catalogs":
                selected_frameworks = {str(value or "").strip() for value in payload.get("framework_id", []) if str(value or "").strip()}
                requested_profile_id = payload.get("profile_id", [""])[0].strip()
                requested_profile_name = payload.get("profile_name", [""])[0].strip()
                connection = ioc_store.connect_db(self.app_config.state_db_path)
                try:
                    ioc_store.init_db(connection)
                    active_profile = ioc_store.get_active_csf_profile(connection)
                    profile_id = requested_profile_id or str(active_profile.get("profile_id") or "")
                    catalogs = ioc_store.list_csf_profile_control_catalogs(connection, profile_id)
                    previous_frameworks = sorted(
                        str(catalog["framework_id"]) for catalog in catalogs if int(catalog.get("profile_is_enabled") or 0)
                    )
                    registered_frameworks = {str(catalog["framework_id"]) for catalog in catalogs}
                    unknown_frameworks = selected_frameworks - registered_frameworks
                    if unknown_frameworks:
                        raise RuntimeError("The selected control catalog is not registered.")
                    for framework_id in registered_frameworks:
                        ioc_store.set_csf_profile_control_catalog_enabled(
                            connection, profile_id, framework_id,
                            framework_id in selected_frameworks, getpass.getuser(),
                        )
                    profile_name = requested_profile_name or str(active_profile.get("profile_name") or "")
                    if previous_frameworks != sorted(selected_frameworks):
                        ioc_store.record_csf_profile_audit_event(
                            connection, profile_name=profile_name, event_type="profile_updated",
                            field_name="control_catalogs", old_value=previous_frameworks,
                            new_value=sorted(selected_frameworks), rationale="Control catalog selection changed.",
                            recorded_by=getpass.getuser(),
                        )
                finally:
                    connection.close()
                label = "catalog" if len(selected_frameworks) == 1 else "catalogs"
                return self.redirect("/profile?name=" + urllib.parse.quote(profile_name, safe="") + "&message=" + urllib.parse.quote(f"Saved {len(selected_frameworks)} selected {label}."))

            if parsed.path == "/set-csf-current-assessment":
                subcategory_id = payload.get("subcategory_id", [""])[0].strip().upper()
                category_id = payload.get("category_id", [""])[0].strip().upper()
                assessment_level = payload.get("assessment_level", [""])[0]
                official_subcategory = csf_catalog.find_official_subcategory(subcategory_id)
                if official_subcategory is None:
                    raise RuntimeError("Choose an official CSF Subcategory before saving an assessment.")
                if category_id != str(official_subcategory.get("category_id") or ""):
                    raise RuntimeError("The selected CSF Category does not match the Subcategory.")
                connection = ioc_store.connect_db(self.app_config.state_db_path)
                try:
                    ioc_store.init_db(connection)
                    active_profile = ioc_store.get_active_csf_profile(connection)
                    ioc_store.set_current_csf_assessment(
                        connection,
                        active_profile.get("profile_id"),
                        subcategory_id,
                        assessment_level,
                        getpass.getuser(),
                    )
                finally:
                    connection.close()
                redirect_params = urllib.parse.urlencode(
                    {
                        "csf_category": category_id,
                        "csf_subcategory": subcategory_id,
                    }
                )
                return self.redirect(return_to + "?" + redirect_params)

            if parsed.path in {"/create-csf-reviewed-action", "/update-csf-reviewed-action", "/delete-csf-reviewed-action", "/create-csf-supporting-basis"}:
                subcategory_id = (payload.get("subcategory_id", [""])[0] or query_params.get("csf_subcategory", [""])[0]).strip().upper()
                category_id = (payload.get("category_id", [""])[0] or query_params.get("csf_category", [""])[0]).strip().upper()
                return_to = (payload.get("return_to", [""])[0] or query_params.get("return_to", ["/"])[0]).strip() or "/"
                if return_to not in allowed_return_routes:
                    return_to = "/"
                official_subcategory = csf_catalog.find_official_subcategory(subcategory_id)
                if official_subcategory is None or category_id != str(official_subcategory.get("category_id") or ""):
                    raise RuntimeError("Choose an official CSF Subcategory before saving a Tile 3 record.")
                connection = ioc_store.connect_db(self.app_config.state_db_path)
                try:
                    ioc_store.init_db(connection)
                    active_profile = ioc_store.get_active_csf_profile(connection)
                    active_profile_id = str(active_profile.get("profile_id") or "")
                    if not active_profile_id:
                        raise RuntimeError("Choose an Organizational Profile before saving a Tile 3 record.")
                    if str(active_profile.get("profile_kind") or "organizational") != "organizational":
                        raise RuntimeError("Frozen base and Community Profiles are read-only. Create or select an Organizational Profile to add actions or evidence.")
                    if parsed.path == "/create-csf-reviewed-action":
                        control_mapping = payload.get("control_mapping", [""])[0].strip()
                        control_framework_id = "nist-sp-800-53-r5.2.0"
                        control_id = ""
                        if control_mapping:
                            control_framework_id, separator, control_id = control_mapping.partition("|")
                            if not separator or not control_framework_id or not control_id:
                                raise RuntimeError("The selected mapped control is invalid.")
                        ioc_store.create_csf_reviewed_action(
                            connection,
                            profile_id=active_profile_id,
                            subcategory_id=subcategory_id,
                            title=payload.get("title", [""])[0],
                            details=payload.get("details", [""])[0],
                            rationale=payload.get("rationale", [""])[0],
                            action_status=payload.get("action_status", [""])[0],
                            progress_note=payload.get("progress_note", [""])[0],
                            control_id=control_id,
                            framework_id=control_framework_id,
                            basis_ids=payload.get("basis_id", []),
                            created_by=getpass.getuser(),
                        )
                    elif parsed.path == "/update-csf-reviewed-action":
                        action_id = (payload.get("action_id", [""])[0] or query_params.get("action_id", [""])[0]).strip()
                        existing = connection.execute(
                            "SELECT subcategory_id FROM csf_reviewed_actions WHERE action_id = ? AND profile_id = ?", (action_id, active_profile_id)
                        ).fetchone()
                        if existing is None or str(existing["subcategory_id"]) != subcategory_id:
                            raise RuntimeError("Choose an action from the selected CSF Subcategory before saving an update.")
                        ioc_store.update_csf_reviewed_action(
                            connection,
                            action_id=action_id,
                            title=payload.get("title", [""])[0],
                            details=payload.get("details", [""])[0],
                            rationale=payload.get("rationale", [""])[0],
                            action_status=payload.get("action_status", [""])[0],
                            progress_note=payload.get("progress_note", [""])[0],
                            updated_by=getpass.getuser(),
                            basis_ids=payload.get("basis_id", []),
                        )
                    elif parsed.path == "/delete-csf-reviewed-action":
                        action_id = (payload.get("action_id", [""])[0] or query_params.get("action_id", [""])[0]).strip()
                        existing = connection.execute(
                            "SELECT subcategory_id FROM csf_reviewed_actions WHERE action_id = ? AND profile_id = ?", (action_id, active_profile_id)
                        ).fetchone()
                        if existing is None or str(existing["subcategory_id"]) != subcategory_id:
                            raise RuntimeError("Choose an action from the selected CSF Subcategory before deleting it.")
                        ioc_store.delete_csf_reviewed_action(connection, action_id)
                    else:
                        ioc_store.create_csf_supporting_basis(
                            connection, profile_id=active_profile_id, subcategory_id=subcategory_id, title=payload.get("title", [""])[0],
                            basis_type=payload.get("basis_type", [""])[0], details=payload.get("details", [""])[0],
                            reference_location=payload.get("reference_location", [""])[0],
                            recorded_on=payload.get("recorded_on", [""])[0], review_on=payload.get("review_on", [""])[0],
                            outcome_link_role=payload.get("outcome_link_role", ["supports_outcome"])[0],
                            assertion_text=payload.get("assertion_text", [""])[0],
                            applicability_note=payload.get("applicability_note", [""])[0],
                            created_by=getpass.getuser(),
                        )
                finally:
                    connection.close()
                return self.redirect(return_to + "?" + urllib.parse.urlencode({"csf_category": category_id, "csf_subcategory": subcategory_id}))

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


def parse_args(default_app_mode: str = "monitoring") -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Codex Monitor management UI.")
    parser.add_argument("--host", default="127.0.0.1", help="Bind address.")
    parser.add_argument("--port", type=int, default=8765, help="Bind port.")
    parser.add_argument("--settings", default=str(Path(__file__).resolve().parent / "codex-monitor.settings.json"), help="Path to codex-monitor.settings.json.")
    parser.add_argument("--open-browser", action="store_true", help="Open the dashboard in the default browser on startup.")
    parser.add_argument("--open-path", default="/", help="Local UI path to open when --open-browser is used.")
    parser.add_argument("--app-mode", choices=("analyst", "monitoring"), default=default_app_mode, help="Run the CSF Analyst or monitoring application surface.")
    return parser.parse_args()


def main(default_app_mode: str = "monitoring") -> int:
    args = parse_args(default_app_mode)
    config = load_settings(Path(args.settings), args.app_mode)
    config.app_mode = args.app_mode
    server = ThreadingHTTPServer((args.host, args.port), CodexUiHandler)
    server.app_config = config  # type: ignore[attr-defined]
    server.snapshot_lock = threading.Lock()  # type: ignore[attr-defined]
    server.ui_snapshot_cache = build_snapshot(config)  # type: ignore[attr-defined]
    open_path = str(args.open_path or "/")
    if not open_path.startswith("/") or open_path.startswith("//"):
        open_path = "/"
    url = f"http://{args.host}:{args.port}{open_path}"
    print(f"{'CSF Analyst UI' if config.app_mode == 'analyst' else 'Codex Monitor UI'} listening on {url}")
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
