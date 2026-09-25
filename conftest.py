"""Pytest bootstrap: force UTF-8 so non-ASCII literals survive Windows ANSI codepage."""

import os

os.environ.setdefault("PYTHONUTF8", "1")
os.environ.setdefault("PYTHONIOENCODING", "utf-8")
