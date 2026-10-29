"""
app.py (AI Detection Runner)
============================
Redirects to dashboard/app.py for convenient execution from both directories.
"""
import runpy
from pathlib import Path

dashboard_app = Path(__file__).resolve().parent.parent / "dashboard" / "app.py"
runpy.run_path(str(dashboard_app), run_name="__main__")
