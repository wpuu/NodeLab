"""Saved-report GUI checks using fictional data and a deterministic Tk facade."""
from __future__ import annotations

import os
import runpy
import sys
import time
import types
from pathlib import Path

import pytest

import nodelab.offline_file as offline_file
from nodelab.inventory import build_input_metadata, build_inventory


_ROOT = Path(__file__).resolve().parents[1]
_SECRET = "FICTIONAL_REPORT_ENTRY_SECRET"
_HOST = "fictional-report-entry.example.invalid"
_PRIVATE = "fictional-private-report-folder"
_URI = f"trojan://{_SECRET}@{_HOST}:443#fictional-report-label"
_RAW = (_URI + "\n" + _URI + "\n").encode("utf-8")


def _loaded(input_format="base64", version=2):
    return {
        "report": build_inventory(_RAW),
        "metadata": build_input_metadata(input_format),
        "marker_schema_version": version,
        # The GUI must use validated records and metadata, rather than show a
        # supplied Markdown document or its arbitrary strings.
        "markdown": "FICTIONAL_UNTRUSTED_MARKDOWN " + _URI,
    }


def _assert_private_absent(text, selected=None):
    for private in (_SECRET, _HOST, _PRIVATE, _URI, "fictional-report-label", "FICTIONAL_UNTRUSTED_MARKDOWN"):
        assert private not in text
    if selected is not None:
        assert str(selected) not in text


class _Widget:
    def __init__(self, parent=None, **kwargs):
        self.options = dict(kwargs)
        self.parent = parent

    def pack(self, **kwargs):
        return None

    def config(self, **kwargs):
        self.options.update(kwargs)

    configure = config

    def __getitem__(self, key):
        return self.options.get(key, "normal" if key == "state" else "")


class _Text(_Widget):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.value = ""

    def delete(self, *args):
        self.value = ""

    def insert(self, index, value):
        self.value += value


class _Button(_Widget):
    def invoke(self):
        if self["state"] != "disabled":
            return self.options["command"]()


class _Combo(_Widget):
    def current(self, index):
        self.index = index

    def get(self):
        return self.options["values"][self.index]


class _Root:
    def __init__(self):
        self.callbacks = []
        self.protocols = {}
        self.clipboard = []
        self.destroyed = False

    def title(self, *args):
        pass

    def geometry(self, *args):
        pass

    def minsize(self, *args):
        pass

    def after(self, delay, callback):
        self.callbacks.append(callback)

    def protocol(self, name, callback):
        self.protocols[name] = callback

    def clipboard_clear(self):
        self.clipboard.clear()

    def clipboard_append(self, text):
        self.clipboard.append(text)

    def destroy(self):
        self.destroyed = True


class _Harness:
    def __init__(self):
        self.root = _Root()
        self.buttons = []
        self.combos = []
        self.texts = []
        self.workers = []
        self.directory_calls = []
        self.messages = []
        self.selections = []

    @property
    def output(self):
        assert len(self.texts) == 1
        return self.texts[0].value

    def poll(self):
        assert self.root.callbacks
        self.root.callbacks.pop(0)()

    def finish(self):
        assert self.workers
        self.workers.pop(0)()
        self.poll()


def _gui_harness(monkeypatch, drive, loader):
    import nodelab.offline_report as offline_report

    harness = _Harness()
    tk = types.ModuleType("tkinter")
    ttk = types.ModuleType("tkinter.ttk")
    filedialog = types.ModuleType("tkinter.filedialog")
    messagebox = types.ModuleType("tkinter.messagebox")
    tk.Tk = lambda: harness.root

    def capture_text(*args, **kwargs):
        widget = _Text(*args, **kwargs)
        harness.texts.append(widget)
        return widget

    def capture_button(*args, **kwargs):
        widget = _Button(*args, **kwargs)
        harness.buttons.append(widget)
        return widget

    def capture_combo(*args, **kwargs):
        widget = _Combo(*args, **kwargs)
        harness.combos.append(widget)
        return widget

    def askdirectory(**kwargs):
        harness.directory_calls.append(kwargs)
        assert harness.selections
        return harness.selections.pop(0)

    def forbidden(*args, **kwargs):
        raise AssertionError("saved-report entry attempted input inspection or publication")

    class DeferredThread:
        def __init__(self, target, **kwargs):
            self.target = target

        def start(self):
            harness.workers.append(self.target)

    tk.Text = capture_text
    ttk.Frame = ttk.Label = _Widget
    ttk.Button = capture_button
    ttk.Combobox = capture_combo
    filedialog.askdirectory = askdirectory
    filedialog.askopenfilename = forbidden
    messagebox.showinfo = lambda *args: harness.messages.append(args)
    tk.ttk, tk.filedialog, tk.messagebox = ttk, filedialog, messagebox
    for name, module in (("tkinter", tk), ("tkinter.ttk", ttk),
                         ("tkinter.filedialog", filedialog), ("tkinter.messagebox", messagebox)):
        monkeypatch.setitem(sys.modules, name, module)
    monkeypatch.setattr(offline_report, "load_reports", loader)
    monkeypatch.setattr(offline_file, "run_file", forbidden)
    monkeypatch.setattr(offline_file, "save_reports", forbidden)
    namespace = runpy.run_path(str(_ROOT / "scripts/nodelab_offline.pyw"), run_name="saved_report_gui_test")
    monkeypatch.setattr(namespace["threading"], "Thread", DeferredThread)
    harness.root.mainloop = lambda: drive(harness)
    assert namespace["_gui"]() == 0
    return harness


@pytest.mark.parametrize("input_format,version", [("uri_lines", 2), ("base64", 2), ("not_recorded", 2), ("not_recorded", 1)])
def test_saved_report_summary_uses_recorded_format_without_showing_saved_markdown(input_format, version):
    namespace = runpy.run_path(str(_ROOT / "scripts/nodelab_offline.pyw"), run_name="saved_report_summary_test")
    summary = namespace["_summary_report"](_loaded(input_format, version))
    assert "报告文件核对通过" in summary
    assert "非空记录：2" in summary and "解析成功：2" in summary
    assert "配置组：1" in summary and "重复记录：1" in summary
    assert "仅核对文件一致性" in summary and "不能证明作者或原始输入" in summary
    if input_format == "base64":
        assert "Base64" in summary and "解码" in summary
    elif input_format == "uri_lines":
        assert "逐行 URI" in summary
    else:
        assert "未记录" in summary and ("不能推断" in summary or "无法推断" in summary)
        assert "输入格式：逐行 URI" not in summary
    _assert_private_absent(summary)


@pytest.mark.parametrize("input_format", ["base64", "not_recorded"])
def test_gui_report_open_is_read_only_busy_guarded_and_uses_saved_format(tmp_path, monkeypatch, input_format):
    selected = tmp_path / _PRIVATE
    reads = []

    def loader(folder):
        reads.append(folder)
        return _loaded(input_format, 1 if input_format == "not_recorded" else 2)

    def drive(h):
        assert len(h.buttons) == 3 and len(h.combos) == 1
        assert "打开报告" in h.buttons[2]["text"] and "核对" in h.buttons[2]["text"]
        h.selections.append(str(selected))
        h.combos[0].current(0)  # Plain input selection cannot override saved provenance.
        h.buttons[2].invoke()
        assert all(button["state"] == "disabled" for button in h.buttons)
        assert h.combos[0]["state"] == "disabled"
        assert reads == [] and len(h.workers) == 1
        assert "报告文件核对通过" not in h.output
        # Invoke callbacks directly to verify their guards, beyond disabled widgets.
        h.buttons[0].options["command"]()
        h.buttons[2].options["command"]()
        assert len(h.directory_calls) == 1 and len(h.workers) == 1
        h.root.protocols["WM_DELETE_WINDOW"]()
        assert h.messages and not h.root.destroyed
        h.finish()
        assert reads == [selected]
        assert all(button["state"] == "normal" for button in h.buttons)
        assert h.combos[0]["state"] == "readonly"
        assert "报告文件核对通过" in h.output
        assert "报告保存到本机" not in h.output
        if input_format == "base64":
            assert "Base64" in h.output and "解码" in h.output
        else:
            assert "未记录" in h.output
            assert "输入格式：逐行 URI" not in h.output
        h.buttons[1].invoke()
        assert len(h.root.clipboard) == 1
        assert "报告文件核对通过" in h.root.clipboard[0]
        _assert_private_absent(h.output + h.root.clipboard[0], selected)

    _gui_harness(monkeypatch, drive, loader)


@pytest.mark.parametrize("failure", ["fixed_error", "unexpected_exception"])
def test_gui_report_failure_clears_previous_summary_and_disables_copy(tmp_path, monkeypatch, failure):
    from nodelab.offline_report import OfflineReportError

    selected = tmp_path / _PRIVATE
    calls = []
    fixed_error = OfflineReportError("REPORT_INVALID")

    def loader(folder):
        calls.append(folder)
        if len(calls) == 1:
            return _loaded()
        if failure == "fixed_error":
            raise fixed_error
        raise OSError(_URI + " " + str(selected))

    def drive(h):
        h.selections.extend([str(selected), str(selected)])
        h.buttons[2].invoke()
        h.finish()
        assert h.buttons[1]["state"] == "normal"
        assert "报告文件核对通过" in h.output
        h.buttons[2].invoke()
        assert all(button["state"] == "disabled" for button in h.buttons)
        assert "报告文件核对通过" not in h.output
        # A direct copy callback cannot recover the previous successful result.
        h.buttons[1].options["command"]()
        assert all("报告文件核对通过" not in text for text in h.root.clipboard)
        h.finish()
        assert h.buttons[1]["state"] == "disabled"
        assert h.buttons[0]["state"] == h.buttons[2]["state"] == "normal"
        assert h.combos[0]["state"] == "readonly"
        assert "错误码：" in h.output
        assert "报告文件核对通过" not in h.output
        if failure == "fixed_error":
            assert fixed_error.code in h.output
        h.buttons[1].options["command"]()
        assert all("报告文件核对通过" not in text for text in h.root.clipboard)
        _assert_private_absent(h.output + "".join(h.root.clipboard), selected)

    _gui_harness(monkeypatch, drive, loader)


@pytest.mark.parametrize("with_previous_success", [False, True])
def test_gui_report_folder_dialog_cancel_performs_no_read_or_write(tmp_path, monkeypatch, with_previous_success):
    reads = []
    selected = tmp_path / _PRIVATE

    def loader(folder):
        reads.append(folder)
        return _loaded()

    def drive(h):
        if with_previous_success:
            h.selections.append(str(selected))
            h.buttons[2].invoke()
            h.finish()
        previous_output = h.output
        previous_copy_state = h.buttons[1]["state"]
        previous_reads = list(reads)
        h.selections.append("")
        h.buttons[2].invoke()
        assert reads == previous_reads and h.workers == []
        assert h.output == previous_output
        assert h.buttons[1]["state"] == previous_copy_state
        assert h.buttons[0]["state"] == h.buttons[2]["state"] == "normal"
        assert h.combos[0]["state"] == "readonly"

    _gui_harness(monkeypatch, drive, loader)


@pytest.mark.skipif(os.name != "nt", reason="saved-report integration requires a real Windows/Tk runner")
def test_windows_gui_saved_report_loads_once_without_rewriting_files(tmp_path, monkeypatch):
    import tkinter as tk
    from tkinter import filedialog, ttk
    import nodelab.offline_report as offline_report

    folder = offline_file.save_reports(build_inventory(_RAW), tmp_path / _PRIVATE, input_format="base64")
    before = {path.name: (path.read_bytes(), path.stat().st_mtime_ns) for path in folder.iterdir()}
    original_load = offline_report.load_reports
    reads = []

    def observed_load(path):
        reads.append(path)
        return original_load(path)

    def forbidden_write(*args, **kwargs):
        raise AssertionError("report reopening must not regenerate saved files")

    monkeypatch.setattr(offline_report, "load_reports", observed_load)
    monkeypatch.setattr(offline_file, "run_file", forbidden_write)
    monkeypatch.setattr(offline_file, "save_reports", forbidden_write)
    monkeypatch.setattr(filedialog, "askdirectory", lambda **kwargs: str(folder))
    window = tk.Tk()
    window.withdraw()
    monkeypatch.setattr(tk, "Tk", lambda: window)
    buttons, combos, clipboard = [], [], []
    original_button, original_combo = ttk.Button, ttk.Combobox

    def capture_button(*args, **kwargs):
        widget = original_button(*args, **kwargs)
        buttons.append(widget)
        return widget

    def capture_combo(*args, **kwargs):
        widget = original_combo(*args, **kwargs)
        combos.append(widget)
        return widget

    monkeypatch.setattr(ttk, "Button", capture_button)
    monkeypatch.setattr(ttk, "Combobox", capture_combo)
    monkeypatch.setattr(window, "clipboard_clear", lambda: None)
    monkeypatch.setattr(window, "clipboard_append", clipboard.append)
    namespace = runpy.run_path(str(_ROOT / "scripts/nodelab_offline.pyw"), run_name="windows_saved_report_gui_test")
    outcome = {}
    deadline = time.monotonic() + 20

    def tick():
        if time.monotonic() > deadline:
            outcome["timeout"] = True
            window.destroy()
            return
        if str(buttons[1]["state"]) == "normal":
            buttons[1].invoke()
            window.destroy()
            return
        window.after(50, tick)

    def begin():
        assert len(buttons) == 3 and len(combos) == 1
        combos[0].current(0)
        buttons[2].invoke()
        window.after(50, tick)

    window.after(100, begin)
    assert namespace["_gui"]() == 0
    assert "timeout" not in outcome
    assert reads == [folder] and len(clipboard) == 1
    assert "报告文件核对通过" in clipboard[0] and "Base64" in clipboard[0]
    _assert_private_absent(clipboard[0], folder)
    after = {path.name: (path.read_bytes(), path.stat().st_mtime_ns) for path in folder.iterdir()}
    assert after == before
