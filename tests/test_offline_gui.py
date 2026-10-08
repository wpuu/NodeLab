"""Exercise the actual Tk widgets on a Windows runner with a fictional file."""
from __future__ import annotations

import os
import runpy
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize("record_count", [1000, 1001])
@pytest.mark.skipif(os.name != "nt", reason="Owner entry targets Windows/Tk")
def test_windows_picker_cancel_then_anonymous_result_and_copy(tmp_path, monkeypatch, record_count):
    import tkinter as tk
    from tkinter import filedialog, ttk

    namespace = runpy.run_path(str(ROOT / "scripts/nodelab_offline.pyw"), run_name="gui_test")
    source = tmp_path / "fictional-private-name.txt"
    source.write_text("trojan://FICTIONAL_GUI_SECRET@fictional-gui-host.example.invalid:443\n" * record_count, encoding="utf-8")
    local = tmp_path / "local"
    monkeypatch.setenv("LOCALAPPDATA", str(local))
    window = tk.Tk()
    window.withdraw()
    monkeypatch.setattr(tk, "Tk", lambda: window)
    buttons = []
    original_button = ttk.Button

    def capture_button(*args, **kwargs):
        button = original_button(*args, **kwargs)
        buttons.append(button)
        return button

    monkeypatch.setattr(ttk, "Button", capture_button)
    selections = iter(["", str(source)])
    monkeypatch.setattr(filedialog, "askopenfilename", lambda **kwargs: next(selections))
    clipboard = []
    monkeypatch.setattr(window, "clipboard_clear", lambda: None)
    monkeypatch.setattr(window, "clipboard_append", clipboard.append)
    outcome = {}
    texts = []
    original_text = tk.Text

    def capture_text(*args, **kwargs):
        widget = original_text(*args, **kwargs)
        texts.append(widget)
        return widget

    monkeypatch.setattr(tk, "Text", capture_text)
    deadline = time.monotonic() + 15

    def tick():
        if time.monotonic() > deadline:
            outcome["timeout"] = True
            window.destroy()
            return
        if record_count > 1000 and str(buttons[0]["state"]) == "normal":
            outcome["error_text"] = texts[0].get("1.0", "end")
            outcome["copy_state"] = str(buttons[1]["state"])
            outcome["output_exists"] = local.exists()
            window.destroy()
            return
        if str(buttons[1]["state"]) == "normal":
            buttons[1].invoke()
            outcome["complete"] = list(local.rglob("COMPLETE.json"))
            window.destroy()
            return
        window.after(50, tick)

    def begin():
        buttons[0].invoke()  # canceled chooser must leave no report tree
        outcome["cancel_created_output"] = local.exists()
        buttons[0].invoke()
        window.after(50, tick)

    window.after(100, begin)
    assert namespace["_gui"]() == 0
    assert "timeout" not in outcome
    assert outcome["cancel_created_output"] is False
    if record_count > 1000:
        assert "INPUT_TOO_MANY_RECORDS" in outcome["error_text"]
        assert outcome["copy_state"] == "disabled"
        assert outcome["output_exists"] is False
        assert clipboard == []
        return
    assert len(outcome["complete"]) == 1
    assert len(clipboard) == 1
    assert "\u76d8\u70b9\u5b8c\u6210" in clipboard[0]
    for private in ("FICTIONAL_GUI_SECRET", "fictional-gui-host", source.name, str(source)):
        assert private not in clipboard[0]

