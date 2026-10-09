"""Owner's offline inventory entry. Raw paths/URIs never go to logs."""
from __future__ import annotations

import json
import os
import queue
import sys
import threading
from pathlib import Path

# Supports the repository and a minimal bundle without installing NodeLab.
_here = Path(__file__).absolute().parent
if not getattr(sys, "frozen", False):
    if (_here / "nodelab").is_dir():
        sys.path.insert(0, str(_here))
    elif (_here.parent / "src" / "nodelab").is_dir():
        sys.path.insert(0, str(_here.parent / "src"))
    else:
        sys.path.insert(0, str(_here))


def install_offline_guard() -> None:
    def guard(event, args):
        if event.startswith("socket.") or event in {"subprocess.Popen", "os.system", "os.posix_spawn", "os.spawn"}:
            raise RuntimeError("OFFLINE_OPERATION_BLOCKED")
    sys.addaudithook(guard)


def _fixed_output(text: str, *, error: bool = False) -> bool:
    stream = sys.stderr if error else sys.stdout
    if stream is None:
        return False
    try:
        print(text, file=stream, flush=True)
    except (OSError, ValueError):
        return False
    return True


def _acceptance_check() -> dict:
    """Exercise only built-in fictional files, under the installed audit guard.

    Blocked API calls are negative controls, not system-wide network monitoring.
    No paths or source text are returned, including after an unexpected failure.
    """
    import base64
    import socket
    import subprocess
    import tempfile
    import tkinter as tk

    from nodelab.offline_file import run_file, save_reports
    from nodelab.offline_report import OfflineReportError, load_reports
    from nodelab.types import PROBE_GATE_OPEN

    frozen = getattr(sys, "frozen", False) is True
    ignore_environment = bool(sys.flags.ignore_environment)

    def require(condition):
        if not condition:
            raise RuntimeError("ACCEPTANCE_FAILED")

    def blocked(operation):
        try:
            operation()
        except RuntimeError as exc:
            require(str(exc) == "OFFLINE_OPERATION_BLOCKED")
        else:
            raise RuntimeError("ACCEPTANCE_FAILED")

    if frozen:
        require(ignore_environment)
        import nodelab
        loader = getattr(getattr(nodelab, "__spec__", None), "loader", None)
        require(type(loader).__module__ == "pyimod02_importers")

    # If the guard is absent, fail before attempting real socket/DNS/Popen APIs.
    blocked(lambda: sys.audit("socket.__new__", None, socket.AF_INET, socket.SOCK_STREAM, 0))
    blocked(lambda: socket.socket())
    blocked(lambda: socket.getaddrinfo("fictional-acceptance.example.invalid", 9))
    blocked(lambda: subprocess.Popen([sys.executable, "-c", "pass"]))
    interpreter = tk.Tcl()
    require(interpreter.eval("expr {1 + 1}") == "2")
    tcl_patchlevel = interpreter.eval("info patchlevel")
    require(tcl_patchlevel in {"8.6.15", "9.0.4"})
    tk_patchlevel = None
    gui_runtime = "NOT_CHECKED_NO_DISPLAY"
    if os.name == "nt":
        window = tk.Tk()
        try:
            window.withdraw()
            window.update_idletasks()
            window.update()
            require(window.state() == "withdrawn")
            tk_patchlevel = window.tk.eval("package provide Tk")
            require(tk_patchlevel == tcl_patchlevel)
            gui_runtime = "WINDOWS_HIDDEN_WINDOW_PASS"
        finally:
            window.destroy()

    def snapshot(paths):
        return {path: (path.read_bytes(), path.stat().st_mtime_ns) for path in paths}

    private_text = (
        "FICTIONAL_PASSWORD_CANARY_A741", "private-host-a741.example.invalid",
        "FICTIONAL_FRAGMENT_CANARY_A741", "FICTIONAL_SECRET_LINE_A741",
        "FICTIONAL_FILENAME_CANARY_A741", "FICTIONAL_MISMATCH_CANARY_A741",
    )
    fictional = (
        b"trojan://FICTIONAL_PASSWORD_CANARY_A741@private-host-a741.example.invalid:443?security=tls#FICTIONAL_FRAGMENT_CANARY_A741\n"
        b"vless://11111111-1111-4111-8111-111111111111@second-fictional.example.invalid:443?encryption=none&security=tls&type=tcp\n"
        b"trojan://FICTIONAL_SECRET_LINE_A741@invalid-fictional.example.invalid:99999\n"
    )
    metadata = {
        "uri_lines": {"input_format": "uri_lines", "line_number_basis": "source_text", "decoding_passes": 0},
        "base64": {"input_format": "base64", "line_number_basis": "decoded_text", "decoding_passes": 1},
        "not_recorded": {"input_format": "not_recorded", "line_number_basis": "parser_text", "decoding_passes": None},
    }
    with tempfile.TemporaryDirectory(prefix="nodelab-fictional-") as temporary:
        root = Path(temporary)
        inputs = [root / "FICTIONAL_FILENAME_CANARY_A741.txt", root / "fictional-wrapped.txt"]
        inputs[0].write_bytes(fictional)
        inputs[1].write_bytes(base64.b64encode(fictional))
        before_inputs = snapshot(inputs)
        folders = []
        reports = []
        for source, input_format in zip(inputs, ("uri_lines", "base64")):
            report, folder = run_file(source, root / "reports", input_format=input_format)
            reports.append(report)
            folders.append((folder, input_format))
        require(reports[0] == reports[1])
        require(reports[0]["summary"]["records"] == 3)
        require(reports[0]["summary"]["parsed"] == 2)
        require(reports[0]["summary"]["invalid"] == 1)
        folders.append((save_reports(reports[0], root / "reports"), "not_recorded"))
        paths = [folder / name for folder, _ in folders
                 for name in ("COMPLETE.json", "inventory.json", "inventory.md")]
        before_reports = snapshot(paths)
        for folder, input_format in folders:
            loaded = load_reports(folder)
            require(loaded["report"] == reports[0])
            require(loaded["metadata"] == metadata[input_format])
            require(loaded["marker_schema_version"] == 2)
            require(loaded["markdown"] == (folder / "inventory.md").read_text(encoding="utf-8"))
            for value in private_text:
                require(value not in loaded["markdown"])
        require(snapshot(inputs) == before_inputs)
        require(snapshot(paths) == before_reports)
        for data, _ in before_reports.values():
            for value in private_text:
                require(value.encode("utf-8") not in data)
        # A separate fictional copy keeps the three successful reports intact.
        bad_folder = save_reports(reports[0], root / "reports", input_format="uri_lines")
        (bad_folder / "inventory.md").write_text(private_text[-1], encoding="utf-8")
        bad_paths = [bad_folder / name for name in ("COMPLETE.json", "inventory.json", "inventory.md")]
        before_bad = snapshot(bad_paths)
        try:
            load_reports(bad_folder)
        except OfflineReportError as exc:
            require(exc.code == "REPORT_MISMATCH" and str(exc) == "REPORT_MISMATCH")
        else:
            raise RuntimeError("ACCEPTANCE_FAILED")
        require(snapshot(bad_paths) == before_bad)
        require(snapshot(inputs) == before_inputs)
        require(snapshot(paths) == before_reports)
        require(not PROBE_GATE_OPEN)
        forbidden = ("nodelab.cli", "nodelab.engine", "nodelab.engine_binary", "nodelab.engine_config",
                     "nodelab.engine_launch", "nodelab.probe", "nodelab.recover", "nodelab.mihomo_config",
                     "nodelab.mihomo_process")
        require(not any(name == prefix or name.startswith(prefix + ".")
                        for name in sys.modules for prefix in forbidden))
    return {
        "acceptance_check": "PASS", "mode": "FICTIONAL_ONLY",
        "network_used": False, "engine_started": False, "frozen": frozen,
        "ignore_environment": ignore_environment,
        "input_formats_checked": ["uri_lines", "base64"],
        "report_round_trips": 3, "report_schema_version": 2,
        "records": 3, "parsed": 2, "invalid": 1,
        "input_unchanged": True, "reports_unchanged": True,
        "markdown_mismatch": "REJECTED", "private_text": "ABSENT",
        "audit_negative_controls": {"socket_create": "BLOCKED", "dns": "BLOCKED", "child_process": "BLOCKED"},
        "tcl_runtime": "PASS", "gui_runtime": gui_runtime,
        "tcl_patchlevel": tcl_patchlevel, "tk_patchlevel": tk_patchlevel,
    }


def _format_summary(input_format: str) -> str:
    return {
        "uri_lines": "逐行 URI（行号为源文本行）",
        "base64": "Base64（行号为解码后的文本行）",
        "not_recorded": "未记录（行号为解析器收到的文本行；不能推断原始包装格式）",
    }.get(input_format, "未记录（不能推断原始包装格式）")


def _count_summary(report: dict) -> str:
    s = report["summary"]
    return (f"非空记录：{s['records']}\n解析成功：{s['parsed']}\n"
            f"不支持：{s['unsupported']}\n格式错误：{s['invalid']}\n"
            f"配置组：{s['unique_configurations']}\n重复记录：{s['duplicate_records']}\n\n"
            "配置组不是独立线路数。来源、授权、出口、稳定性仍未知。")


def _summary(report: dict, input_format: str = "uri_lines") -> str:
    return ("盘点完成（未联网测量）\n"
            f"输入格式：{_format_summary(input_format)}\n" + _count_summary(report))


def _summary_report(loaded: dict) -> str:
    return ("报告文件核对通过（本次核对未联网）\n"
            f"输入格式：{_format_summary(loaded['metadata']['input_format'])}\n"
            + _count_summary(loaded["report"])
            + "\n仅核对文件一致性，不能证明作者或原始输入。")


def _gui() -> int:
    try:
        import tkinter as tk
        from tkinter import filedialog, messagebox, ttk
    except ImportError:
        print("需要包含 Tk 的 Python 3.12 或更高版本；程序没有自动安装。", file=sys.stderr)
        return 2
    from nodelab.offline_file import OfflineFileError, run_file
    from nodelab.offline_report import OfflineReportError, load_reports
    try:
        root = tk.Tk()
    except Exception:
        print("图形界面不可用；尚未读取节点文件。", file=sys.stderr)
        return 2
    root.title("NodeLab 本机离线盘点")
    root.geometry("640x540")
    root.minsize(570, 480)
    frame = ttk.Frame(root, padding=18)
    frame.pack(fill="both", expand=True)
    ttk.Label(frame, text="本机节点盘点与报告核对", font=("", 14)).pack(anchor="w")
    ttk.Label(frame, text="选择逐行 URI 或 Base64 订阅文本；所选原始文件最多512KiB。仅盘点，不连接节点或上传资料。", wraplength=600).pack(anchor="w", pady=(10, 6))
    ttk.Label(frame, text="也可打开已保存的报告目录，只读核对三个报告文件。请选择已下载的本地文件；网络盘、重解析点和云占位文件会被拒绝。", wraplength=600).pack(anchor="w")
    formats = {"逐行 URI": "uri_lines", "Base64 订阅文本": "base64"}
    format_row = ttk.Frame(frame)
    format_row.pack(fill="x", pady=(8, 0))
    ttk.Label(format_row, text="输入格式：").pack(side="left")
    format_choice = ttk.Combobox(format_row, values=tuple(formats), state="readonly", width=24)
    format_choice.current(0)
    format_choice.pack(side="left")
    output = tk.Text(frame, height=14, wrap="word", state="disabled")
    output.pack(fill="both", expand=True, pady=12)
    events = queue.Queue()
    state = {"running": False, "summary": ""}

    def display(text):
        output.config(state="normal")
        output.delete("1.0", "end")
        output.insert("1.0", text)
        output.config(state="disabled")

    def start(message):
        state["running"] = True
        state["summary"] = ""
        button.config(state="disabled")
        copy_button.config(state="disabled")
        report_button.config(state="disabled")
        format_choice.config(state="disabled")
        display(message)

    def choose():
        if state["running"]:
            return
        selected = filedialog.askopenfilename(title="选择本机节点文本", filetypes=[("文本", "*.txt"), ("所有文件", "*")])
        if not selected:
            return
        input_format = formats.get(format_choice.get())
        start("正在盘点，请稍候……")

        def work():
            try:
                local = os.environ.get("LOCALAPPDATA")
                if not local or os.name != "nt":
                    raise OfflineFileError("OUTPUT_UNSAFE")
                report, folder = run_file(Path(selected), Path(local) / "NodeLab" / "Reports", input_format=input_format)
                events.put(("inventory_ok", _summary(report, input_format), folder.name))
            except OfflineFileError as exc:
                events.put(("error", exc.code, None))
            except Exception:
                events.put(("error", "INVENTORY_FAILED", None))
        threading.Thread(target=work, daemon=True).start()

    def open_report():
        if state["running"]:
            return
        selected = filedialog.askdirectory(title="选择完整的本机报告目录", mustexist=True)
        if not selected:
            return
        start("正在核对报告文件，请稍候……")

        def work():
            try:
                loaded = load_reports(Path(selected))
                events.put(("report_ok", _summary_report(loaded), None))
            except OfflineReportError as exc:
                events.put(("error", exc.code, "report"))
            except Exception:
                events.put(("error", "REPORT_INVALID", "report"))
        threading.Thread(target=work, daemon=True).start()

    def poll():
        try:
            kind, text, folder = events.get_nowait()
        except queue.Empty:
            root.after(100, poll)
            return
        state["running"] = False
        button.config(state="normal")
        report_button.config(state="normal")
        format_choice.config(state="readonly")
        if kind == "inventory_ok":
            state["summary"] = text
            display(text + "\n\n报告保存到本机：\n%LOCALAPPDATA%\\NodeLab\\Reports\\" + folder)
            copy_button.config(state="normal")
        elif kind == "report_ok":
            state["summary"] = text
            display(text)
            copy_button.config(state="normal")
        else:
            state["summary"] = ""
            copy_button.config(state="disabled")
            if folder == "report":
                display("报告核对未完成。错误码：" + text + "\n报告文件没有被修改。")
            else:
                display("盘点未完成。错误码：" + text + "\n原始文件没有被修改。")
        root.after(100, poll)

    def copy():
        if state["running"] or not state["summary"]:
            return
        root.clipboard_clear()
        root.clipboard_append(state["summary"])

    def close():
        if state["running"]:
            messagebox.showinfo("正在处理", "请等本次处理完成后关闭。")
            return
        root.destroy()

    controls = ttk.Frame(frame)
    controls.pack(fill="x")
    button = ttk.Button(controls, text="选择文件并盘点", command=choose)
    button.pack(side="left")
    copy_button = ttk.Button(controls, text="复制匿名摘要", command=copy, state="disabled")
    copy_button.pack(side="right")
    report_button = ttk.Button(controls, text="打开报告并核对", command=open_report)
    report_button.pack(side="left", padx=(8, 0))
    root.protocol("WM_DELETE_WINDOW", close)
    root.after(100, poll)
    root.mainloop()
    return 0


def main() -> int:
    if sys.version_info < (3, 12):
        _fixed_output("需要 Python 3.12 或更高版本；程序没有自动安装。", error=True)
        return 2
    try:
        install_offline_guard()
        if sys.argv[1:] == ["--self-check"]:
            import base64
            from nodelab.inventory import build_inventory
            from nodelab.subscription_input import decode_subscription_input
            fictional = b"trojan://FAKE_ONLY@demo.example.invalid:443\n"
            report = build_inventory(fictional)
            wrapped = build_inventory(decode_subscription_input(base64.b64encode(fictional), input_format="base64"))
            if report["summary"]["parsed"] != 1 or wrapped != report:
                raise RuntimeError("CHECK_FAILED")
            return 0 if _fixed_output(json.dumps({"self_check": "PASS", "mode": "FICTIONAL_ONLY", "network_used": False})) else 2
        if sys.argv[1:] == ["--acceptance-check"]:
            try:
                result = _acceptance_check()
            except Exception:
                _fixed_output("ACCEPTANCE_FAILED", error=True)
                return 2
            if not _fixed_output(json.dumps(result, sort_keys=True)):
                _fixed_output("ACCEPTANCE_OUTPUT_UNAVAILABLE", error=True)
                return 2
            return 0
        if sys.argv[1:]:
            _fixed_output("ARGUMENTS_FORBIDDEN", error=True)
            return 2
        return _gui()
    except Exception:
        _fixed_output("启动失败（ENTRY_FAILED）；尚未完成盘点。", error=True)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
