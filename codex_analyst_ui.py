"""CSF Analyst application entry point.

The analyst UI deliberately excludes local-PC scanning, alert delivery, and
monitor report routes.  Those operational functions are served by the separate
Codex Monitor app through ``codex_monitor_ui.py``.
"""

from codex_monitor_ui import main


if __name__ == "__main__":
    raise SystemExit(main(default_app_mode="analyst"))
