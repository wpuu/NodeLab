"""Bounded synthetic regression, runnable with unittest or pytest; no network."""
from __future__ import annotations

import importlib.util
import json
import os
import runpy
import subprocess
import sys
import tempfile
import time
import types
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from nodelab.inventory import (MAX_INPUT_BYTES, MAX_INPUT_RECORDS, InventoryInputError,
                               build_inventory, render_inventory_report)
from nodelab.offline_file import OfflineFileError, run_file
from nodelab.types import PROBE_GATE_OPEN

URI = b"trojan://FICTIONAL_LIMIT_SECRET@limit.example.invalid:443"
CODE = "INPUT_TOO_MANY_RECORDS"


def data(count, *, crlf=False, bom=False, blank=False):
    sep = b"\r\n" if crlf else b"\n"
    body = sep.join([URI] * count) + sep
    if blank:
        body = b" \t\v\f" + sep + body.replace(sep, sep + b" \t" + sep)
    return (b"\xef\xbb\xbf" if bom else b"") + body


class InventoryLimitTests(unittest.TestCase):
    def test_exact_record_limit_and_nonsecret_output_budget(self):
        self.assertEqual(MAX_INPUT_RECORDS, 1000)
        for count in (999, 1000):
            with self.subTest(count=count):
                result = build_inventory(data(count))
                self.assertEqual(result["summary"]["records"], count)
                self.assertEqual(result["summary"]["parsed"], count)
                self.assertTrue(result["complete"])
                encoded = json.dumps(result, indent=2) + render_inventory_report(result)
                self.assertLess(len(encoded.encode()), 1024 * 1024)
                self.assertNotIn("FICTIONAL_LIMIT_SECRET", encoded)
                self.assertNotIn("limit.example.invalid", encoded)
        self.assertFalse(PROBE_GATE_OPEN)

    def test_bom_crlf_and_blank_lines_match_parser_counting(self):
        for crlf in (False, True):
            for bom in (False, True):
                with self.subTest(crlf=crlf, bom=bom):
                    result = build_inventory(data(1000, crlf=crlf, bom=bom, blank=True))
                    self.assertEqual(result["summary"]["records"], 1000)
                    self.assertEqual(result["summary"]["blank_lines"], 1001)
                    with self.assertRaises(InventoryInputError) as caught:
                        build_inventory(data(1001, crlf=crlf, bom=bom, blank=True))
                    self.assertEqual(caught.exception.code, CODE)

    def test_all_nonblank_statuses_count_before_parser(self):
        for row in (URI, b"x", b"\xff", b"ss://FICTIONAL_ONLY"):
            with self.subTest(row=row):
                with patch("nodelab.inventory.parse_uris", side_effect=AssertionError("parser called")):
                    with self.assertRaises(InventoryInputError) as caught:
                        build_inventory((row + b"\n") * 1001)
                self.assertEqual(caught.exception.code, CODE)
                self.assertEqual(str(caught.exception), CODE)

    def test_empty_and_many_blank_lines_do_not_consume_records(self):
        for content in (b"", b"\xef\xbb\xbf", b"\r\n" * 1500, b"\n" * MAX_INPUT_BYTES):
            self.assertEqual(build_inventory(content)["summary"]["records"], 0)

    def test_byte_limit_remains_independent(self):
        with self.assertRaises(InventoryInputError) as caught:
            build_inventory(b" " * (MAX_INPUT_BYTES + 1))
        self.assertEqual(caught.exception.code, "INPUT_TOO_LARGE")

    def test_public_validator_rejects_oversized_forged_report(self):
        # Only construct a small fixture with a temporarily raised producer limit.
        with patch("nodelab.inventory.MAX_INPUT_RECORDS", 1001):
            result = build_inventory(data(1001))
        with self.assertRaises(InventoryInputError) as caught:
            render_inventory_report(result)
        self.assertEqual(caught.exception.code, "PUBLIC_SCHEMA_REJECTED")

    def test_file_limit_rejects_before_any_report_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, output = root / "fictional.txt", root / "never-created"
            source.write_bytes(data(1001, bom=True, crlf=True, blank=True))
            before = source.read_bytes()
            with self.assertRaises(OfflineFileError) as caught:
                run_file(source, output)
            self.assertEqual(caught.exception.code, CODE)
            self.assertEqual(source.read_bytes(), before)
            self.assertFalse(output.exists())
            source.write_bytes(data(1000))
            report, folder = run_file(source, output)
            self.assertEqual(report["summary"]["records"], 1000)
            self.assertTrue((folder / "COMPLETE.json").is_file())
            self.assertLess(sum(p.stat().st_size for p in folder.iterdir()), 1024 * 1024)

    def test_cli_file_and_stdin_final_module_both_formats(self):
        environment = dict(os.environ, PYTHONPATH=str(ROOT / "src"), PYTHONUTF8="1")
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "fictional.txt"
            for command in ("inventory-file", "inventory-stdin"):
                for fmt in ("json", "markdown"):
                    for count in (1000, 1001):
                        with self.subTest(command=command, fmt=fmt, count=count):
                            content = data(count, bom=True, crlf=True, blank=True)
                            source.write_bytes(content)
                            args = [sys.executable, "-m", "nodelab.cli", command, "--format", fmt]
                            if command == "inventory-file":
                                args.extend(["--file", str(source)])
                            completed = subprocess.run(args, input=content, capture_output=True,
                                                       env=environment, timeout=20)
                            out = completed.stdout.decode("utf-8")
                            self.assertEqual(completed.stderr, b"")
                            self.assertNotIn("FICTIONAL_LIMIT_SECRET", out)
                            self.assertNotIn(str(source), out)
                            self.assertEqual(completed.returncode, 0 if count == 1000 else 2)
                            if count == 1001:
                                result = json.loads(out)
                                self.assertEqual(result["error_code"], CODE)
                                self.assertFalse(result["complete"])
                                self.assertFalse(result["network_used"])
                                self.assertNotIn("summary", result)
                            elif fmt == "json":
                                self.assertEqual(json.loads(out)["summary"]["records"], 1000)
                            else:
                                self.assertIn("| 非空记录 | 1000 |", out)

    def test_headless_gui_handler_rejects_then_recovers(self):
        # Exercise the final GUI choose/worker/poll callbacks. Tk controls and
        # picker are simulated: this is explicitly NOT a Windows GUI test.
        callbacks, buttons, texts = [], [], []
        class Widget:
            def __init__(self, *args, **kwargs):
                self.state = kwargs.get("state", "normal")
                self.command = kwargs.get("command")
                self.text = ""
            def pack(self, **kwargs): pass
            def config(self, **kwargs): self.state = kwargs.get("state", self.state)
            def delete(self, *args): self.text = ""
            def insert(self, _, value): self.text = value
        class Window:
            def title(self, *_): pass
            def geometry(self, *_): pass
            def minsize(self, *_): pass
            def protocol(self, *_): pass
            def after(self, _, callback): callbacks.append(callback)
            def mainloop(self):
                buttons[0].command()
                deadline = time.monotonic() + 10
                while time.monotonic() < deadline:
                    if callbacks: callbacks.pop(0)()
                    if buttons[0].state == "normal": break
                    time.sleep(.005)
                else: raise AssertionError("GUI callback timeout")
        def text(*args, **kwargs):
            obj = Widget(*args, **kwargs); texts.append(obj); return obj
        def button(*args, **kwargs):
            obj = Widget(*args, **kwargs); buttons.append(obj); return obj
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); source = root / "fictional.txt"
            tk = types.ModuleType("tkinter")
            tk.Tk, tk.Text = Window, text
            tk.ttk = types.SimpleNamespace(Frame=Widget, Label=Widget, Button=button)
            tk.filedialog = types.SimpleNamespace(askopenfilename=lambda **kwargs: str(source))
            tk.messagebox = types.SimpleNamespace(showinfo=lambda *args: None)
            namespace = runpy.run_path(str(ROOT / "scripts/nodelab_offline.pyw"), run_name="gui_limit_test")
            # Change only the GUI module's platform facade, not pathlib/os.
            namespace["_gui"].__globals__["os"] = types.SimpleNamespace(
                name="nt", environ={"LOCALAPPDATA": str(root / "local")})
            with patch.dict(sys.modules, {"tkinter": tk}):
                source.write_bytes(data(1001))
                self.assertEqual(namespace["_gui"](), 0)
                self.assertIn(CODE, texts[-1].text)
                self.assertIn("未生成报告", texts[-1].text)
                self.assertEqual(buttons[-1].state, "disabled")
                self.assertFalse((root / "local").exists())
                callbacks.clear(); buttons.clear(); texts.clear()
                source.write_bytes(data(1000))
                self.assertEqual(namespace["_gui"](), 0)
                self.assertIn("盘点完成", texts[-1].text)
                self.assertEqual(buttons[-1].state, "normal")
                self.assertEqual(len(list((root / "local").rglob("COMPLETE.json"))), 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
