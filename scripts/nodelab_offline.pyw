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


def _summary(report: dict) -> str:
    s = report["summary"]
    return ("盘点完成（未联网测量）\n"
            f"非空记录：{s['records']}\n解析成功：{s['parsed']}\n"
            f"不支持：{s['unsupported']}\n格式错误：{s['invalid']}\n"
            f"配置组：{s['unique_configurations']}\n重复记录：{s['duplicate_records']}\n\n"
            "配置组不是独立线路数。来源、授权、出口、稳定性仍未知。")


def _gui() -> int:
    try:
        import tkinter as tk
        from tkinter import filedialog, messagebox, ttk
    except ImportError:
        print("需要包含 Tk 的 Python 3.12 或更高版本；程序没有自动安装。", file=sys.stderr)
        return 2
    from nodelab.offline_file import OfflineFileError, run_file
    try:
        root = tk.Tk()
    except Exception:
        print("图形界面不可用；尚未读取节点文件。", file=sys.stderr)
        return 2
    root.title("NodeLab 本机离线盘点")
    root.geometry("580x430")
    root.minsize(500, 380)
    frame = ttk.Frame(root, padding=18)
    frame.pack(fill="both", expand=True)
    ttk.Label(frame, text="选择一份本机节点文本，生成匿名统计", font=("", 14)).pack(anchor="w")
    ttk.Label(frame, text="支持逐行文本，最多512KiB。仅盘点，不连接节点或上传资料。", wraplength=530).pack(anchor="w", pady=(10, 6))
    ttk.Label(frame, text="请选择已下载的本地文件；网络盘、重解析点和云占位文件会被拒绝。", wraplength=530).pack(anchor="w")
    output = tk.Text(frame, height=12, wrap="word", state="disabled")
    output.pack(fill="both", expand=True, pady=12)
    events = queue.Queue()
    state = {"running": False, "summary": ""}

    def display(text):
        output.config(state="normal")
        output.delete("1.0", "end")
        output.insert("1.0", text)
        output.config(state="disabled")

    def choose():
        if state["running"]:
            return
        selected = filedialog.askopenfilename(title="选择本机节点文本", filetypes=[("文本", "*.txt"), ("所有文件", "*")])
        if not selected:
            return
        state["running"] = True
        button.config(state="disabled")
        copy_button.config(state="disabled")
        display("正在盘点，请稍候……")

        def work():
            try:
                local = os.environ.get("LOCALAPPDATA")
                if not local or os.name != "nt":
                    raise OfflineFileError("OUTPUT_UNSAFE")
                report, folder = run_file(Path(selected), Path(local) / "NodeLab" / "Reports")
                events.put(("ok", _summary(report), folder.name))
            except OfflineFileError as exc:
                events.put(("error", exc.code, None))
            except Exception:
                events.put(("error", "INVENTORY_FAILED", None))
        threading.Thread(target=work, daemon=True).start()

    def poll():
        try:
            kind, text, folder = events.get_nowait()
        except queue.Empty:
            root.after(100, poll)
            return
        state["running"] = False
        button.config(state="normal")
        if kind == "ok":
            state["summary"] = text
            display(text + "\n\n报告保存到本机：\n%LOCALAPPDATA%\\NodeLab\\Reports\\" + folder)
            copy_button.config(state="normal")
        else:
            state["summary"] = ""
            display("盘点未完成。错误码：" + text + "\n原始文件没有被修改。")
        root.after(100, poll)

    def copy():
        root.clipboard_clear()
        root.clipboard_append(state["summary"])

    def close():
        if state["running"]:
            messagebox.showinfo("正在盘点", "请等本次处理完成后关闭。")
            return
        root.destroy()

    controls = ttk.Frame(frame)
    controls.pack(fill="x")
    button = ttk.Button(controls, text="选择文件并盘点", command=choose)
    button.pack(side="left")
    copy_button = ttk.Button(controls, text="复制匿名摘要", command=copy, state="disabled")
    copy_button.pack(side="right")
    root.protocol("WM_DELETE_WINDOW", close)
    root.after(100, poll)
    root.mainloop()
    return 0


def main() -> int:
    if sys.version_info < (3, 12):
        print("需要 Python 3.12 或更高版本；程序没有自动安装。", file=sys.stderr)
        return 2
    install_offline_guard()
    try:
        if sys.argv[1:] == ["--self-check"]:
            from nodelab.inventory import build_inventory
            report = build_inventory(b"trojan://FAKE_ONLY@demo.example.invalid:443\n")
            if report["summary"]["parsed"] != 1:
                raise RuntimeError("CHECK_FAILED")
            print(json.dumps({"self_check": "PASS", "mode": "FICTIONAL_ONLY", "network_used": False}))
            return 0
        if sys.argv[1:]:
            print("ARGUMENTS_FORBIDDEN", file=sys.stderr)
            return 2
        return _gui()
    except Exception:
        print("启动失败（ENTRY_FAILED）；尚未完成盘点。", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
