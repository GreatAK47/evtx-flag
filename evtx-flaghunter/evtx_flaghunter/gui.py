"""Graphical interface - the primary interaction form (design doc 4.2).

Single window, three zones:

* top bar    - import buttons, preset selector, one-click scan
* left panel - all options exposed as widgets (zero typing required)
* right side - file list, result table, record detail viewer
* status bar - progress + summary + export

Drag & drop of files / folders / zip archives is enabled through
``tkinterdnd2`` when available; buttons and path paste always work as
fallbacks (design doc 4.3.1).
"""

from __future__ import annotations

import tempfile
import zipfile
from pathlib import Path
from typing import Any

import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from evtx_flaghunter import exporter
from evtx_flaghunter.detect import detect_file
from evtx_flaghunter.model import FileEntry, RecordHit, ScanConfig
from evtx_flaghunter.presets import PRESETS
from evtx_flaghunter.scanner import (
    EV_DONE,
    EV_ERROR,
    EV_FILE_DONE,
    EV_FILE_PROGRESS,
    EV_FILE_START,
    EV_HIT,
    EV_TOTAL,
    Scanner,
)

try:  # drag & drop support is optional at runtime
    from tkinterdnd2 import DND_FILES, TkinterDnD

    _HAS_DND = True
except ImportError:  # pragma: no cover - exercised on slim installs
    DND_FILES = "<<Drop>>"
    TkinterDnD = None  # type: ignore[assignment]
    _HAS_DND = False


class FlagHunterApp:
    """Main application window."""

    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.entries: list[FileEntry] = []
        self.hits: list[RecordHit] = []
        self._events: Any = None
        self._scanning = False
        self._temp_dirs: list[str] = []
        self._build_ui()
        if _HAS_DND:
            root.drop_target_register(DND_FILES)
            root.dnd_bind("<<Drop>>", self._on_drop)

    # ------------------------------------------------------------------ UI

    def _build_ui(self) -> None:
        """Create every widget (design doc layout sketch, section 4.2)."""
        self.root.title("EVTX-FlagHunter - CTF 事件日志 Flag 检索")
        self.root.geometry("1100x720")
        self.root.minsize(900, 600)

        top = ttk.Frame(self.root, padding=6)
        top.pack(fill=tk.X)
        ttk.Button(top, text="添加文件", command=self._add_files).pack(side=tk.LEFT)
        ttk.Button(top, text="添加文件夹", command=self._add_dir).pack(
            side=tk.LEFT, padx=4
        )
        ttk.Label(top, text="模板:").pack(side=tk.LEFT, padx=(12, 2))
        self.preset_var = tk.StringVar(value="flag")
        ttk.Combobox(
            top,
            textvariable=self.preset_var,
            values=sorted(PRESETS),
            width=10,
            state="readonly",
        ).pack(side=tk.LEFT)
        self.scan_btn = ttk.Button(
            top, text="\u25b6 开始检索", command=self._start_scan
        )
        self.scan_btn.pack(side=tk.LEFT, padx=12)

        body = ttk.Frame(self.root)
        body.pack(fill=tk.BOTH, expand=True)

        # Left options panel --------------------------------------------
        left = ttk.LabelFrame(body, text="选项", padding=8)
        left.pack(side=tk.LEFT, fill=tk.Y, padx=6, pady=4)

        self.var_ignore_case = tk.BooleanVar(value=True)
        self.var_auto_decode = tk.BooleanVar(value=True)
        self.var_nested = tk.BooleanVar(value=True)
        self.var_skip_broken = tk.BooleanVar(value=False)

        for text, var in (
            ("忽略大小写", self.var_ignore_case),
            ("自动解码显示 (Base64/Hex)", self.var_auto_decode),
            ("嵌套解码匹配 (编码藏匿)", self.var_nested),
            ("跳过损坏文件", self.var_skip_broken),
        ):
            ttk.Checkbutton(left, text=text, variable=var).pack(
                anchor=tk.W, pady=2
            )

        ttk.Separator(left).pack(fill=tk.X, pady=6)
        ttk.Label(left, text="自定义关键词 (空格分隔):").pack(anchor=tk.W)
        self.ent_keywords = ttk.Entry(left, width=28)
        self.ent_keywords.pack(fill=tk.X, pady=2)
        ttk.Label(left, text="正则表达式 (空格分隔):").pack(anchor=tk.W, pady=(6, 0))
        self.ent_regex = ttk.Entry(left, width=28)
        self.ent_regex.pack(fill=tk.X, pady=2)
        ttk.Label(left, text="提取正则 (如 flag\\{[^}]+\\}):").pack(
            anchor=tk.W, pady=(6, 0)
        )
        self.ent_extract = ttk.Entry(left, width=28)
        self.ent_extract.pack(fill=tk.X, pady=2)

        ttk.Separator(left).pack(fill=tk.X, pady=6)
        ttk.Label(left, text="事件ID 过滤:").pack(anchor=tk.W)
        self.ent_eid = ttk.Entry(left, width=28)
        self.ent_eid.pack(fill=tk.X, pady=2)
        ttk.Label(left, text="时间范围 since (UTC):").pack(anchor=tk.W, pady=(6, 0))
        self.ent_since = ttk.Entry(left, width=28)
        self.ent_since.pack(fill=tk.X, pady=2)
        ttk.Label(left, text="时间范围 until (UTC):").pack(anchor=tk.W, pady=(6, 0))
        self.ent_until = ttk.Entry(left, width=28)
        self.ent_until.pack(fill=tk.X, pady=2)
        ttk.Label(left, text="每文件最多输出:").pack(anchor=tk.W, pady=(6, 0))
        self.ent_top = ttk.Spinbox(left, from_=0, to=100000, width=10)
        self.ent_top.set(0)
        self.ent_top.pack(anchor=tk.W, pady=2)

        # Right side: files / results / detail ----------------------------
        right = ttk.PanedWindow(body, orient=tk.VERTICAL)
        right.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        file_frame = ttk.LabelFrame(right, text="文件列表 (支持拖拽导入)", padding=4)
        self.file_tree = ttk.Treeview(
            file_frame,
            columns=("fmt", "name", "size", "records", "hits", "note"),
            show="headings",
            height=6,
        )
        for col, text, width in (
            ("fmt", "格式", 80),
            ("name", "文件", 320),
            ("size", "大小", 90),
            ("records", "记录数", 80),
            ("hits", "命中", 60),
            ("note", "备注", 160),
        ):
            self.file_tree.heading(col, text=text)
            self.file_tree.column(col, width=width, anchor=tk.W)
        self.file_tree.pack(fill=tk.BOTH, expand=True)
        right.add(file_frame, weight=2)

        result_frame = ttk.LabelFrame(right, text="检索结果 (双击查看详情)", padding=4)
        self.result_tree = ttk.Treeview(
            result_frame,
            columns=("time", "eid", "channel", "kw", "ctx", "file"),
            show="headings",
            height=8,
        )
        for col, text, width in (
            ("time", "时间", 150),
            ("eid", "事件ID", 60),
            ("channel", "通道", 90),
            ("kw", "关键词", 90),
            ("ctx", "命中片段", 420),
            ("file", "文件", 120),
        ):
            self.result_tree.heading(col, text=text)
            self.result_tree.column(col, width=width, anchor=tk.W)
        self.result_tree.pack(fill=tk.BOTH, expand=True)
        self.result_tree.bind("<<TreeviewSelect>>", self._on_select_result)
        right.add(result_frame, weight=3)

        detail_frame = ttk.LabelFrame(right, text="记录详情", padding=4)
        btns = ttk.Frame(detail_frame)
        btns.pack(fill=tk.X)
        ttk.Button(btns, text="复制命中片段", command=self._copy_context).pack(
            side=tk.LEFT
        )
        ttk.Button(btns, text="复制完整记录", command=self._copy_content).pack(
            side=tk.LEFT, padx=4
        )
        ttk.Button(btns, text="导出 JSON", command=lambda: self._export("json")).pack(
            side=tk.RIGHT
        )
        ttk.Button(btns, text="导出 CSV", command=lambda: self._export("csv")).pack(
            side=tk.RIGHT, padx=4
        )
        self.detail = tk.Text(
            detail_frame, height=8, wrap=tk.NONE, state=tk.DISABLED,
            font=("Consolas", 9),
        )
        ysb = ttk.Scrollbar(detail_frame, orient=tk.VERTICAL, command=self.detail.yview)
        self.detail.configure(yscrollcommand=ysb.set)
        self.detail.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        ysb.pack(side=tk.RIGHT, fill=tk.Y)
        right.add(detail_frame, weight=3)

        # Status bar -------------------------------------------------------
        status = ttk.Frame(self.root, padding=4)
        status.pack(fill=tk.X)
        self.progress = ttk.Progressbar(status, mode="determinate", length=260)
        self.progress.pack(side=tk.LEFT)
        self.status_var = tk.StringVar(value="拖入 .evtx 文件或文件夹开始")
        ttk.Label(status, textvariable=self.status_var).pack(side=tk.LEFT, padx=8)

    # ------------------------------------------------------------- import

    def _add_files(self) -> None:
        paths = filedialog.askopenfilenames(
            title="选择事件日志",
            filetypes=[("事件日志", "*.evtx *.evt *.zip"), ("所有文件", "*.*")],
        )
        self._import_paths(list(paths))

    def _add_dir(self) -> None:
        path = filedialog.askdirectory(title="选择文件夹 (递归导入)")
        if path:
            self._import_paths([path])

    def _on_drop(self, event: Any) -> None:
        """Handle a drag & drop of files/folders (design doc 4.3.1)."""
        try:
            paths = [str(p) for p in self.root.tk.splitlist(event.data)]
        except Exception:  # noqa: BLE001 - malformed drop payload
            paths = [event.data]
        self._import_paths(paths)

    def _import_paths(self, paths: list[str]) -> None:
        """Detect and register imported paths; show badges immediately."""
        existing = {entry.path for entry in self.entries}
        added = 0
        for raw in paths:
            path = Path(raw)
            candidates: list[Path] = []
            if path.is_dir():
                candidates = sorted(path.rglob("*"))
            elif path.suffix.lower() == ".zip" and path.is_file():
                candidates = self._extract_zip(path)
            elif path.is_file():
                candidates = [path]
            for candidate in candidates:
                if not candidate.is_file():
                    continue
                key = str(candidate)
                if key in existing:
                    continue
                existing.add(key)
                detected = detect_file(candidate)
                self.entries.append(
                    FileEntry(
                        path=key,
                        fmt=detected.fmt,
                        note=detected.note,
                        size=candidate.stat().st_size,
                    )
                )
                self._append_file_row(self.entries[-1])
                added += 1
        self.status_var.set(f"导入 {added} 个文件，共 {len(self.entries)} 个待扫描")

    def _extract_zip(self, path: Path) -> list[Path]:
        """Extract a zip archive into a temp dir and return inner files."""
        target = tempfile.mkdtemp(prefix="evtxfh_zip_")
        self._temp_dirs.append(target)
        try:
            with zipfile.ZipFile(path) as zf:
                zf.extractall(target)
        except (zipfile.BadZipFile, OSError) as exc:
            messagebox.showwarning("解压失败", f"{path.name}: {exc}")
            return [path]
        return sorted(Path(target).rglob("*"))

    def _append_file_row(self, entry: FileEntry) -> None:
        name = Path(entry.path).name
        size_kb = f"{entry.size / 1024:.0f} KB" if entry.size else ""
        self.file_tree.insert(
            "",
            tk.END,
            iid=entry.path,
            values=(entry.fmt, name, size_kb, entry.records, entry.hits,
                    entry.note or entry.error),
        )

    # --------------------------------------------------------------- scan

    def _start_scan(self) -> None:
        """One-click scan entry point (zero configuration required)."""
        if self._scanning:
            return
        if not self.entries:
            messagebox.showinfo("提示", "请先拖入或添加 .evtx 文件")
            return
        config = self._build_config()
        self._clear_results()
        self._scanning = True
        self.scan_btn.state(["disabled"])
        self.progress.configure(value=0, mode="determinate")
        self.status_var.set("扫描中...")

        scanner = Scanner(config)
        self._events, _thread = scanner.start_async()
        self.root.after(80, self._poll_events)

    def _build_config(self) -> ScanConfig:
        """Collect widget state into a ScanConfig."""
        split = lambda text: [t for t in text.replace(",", " ").split() if t]
        return ScanConfig(
            paths=[entry.path for entry in self.entries],
            keywords=split(self.ent_keywords.get()),
            regex_patterns=split(self.ent_regex.get()),
            preset=self.preset_var.get(),
            ignore_case=self.var_ignore_case.get(),
            extract=self.ent_extract.get().strip() or None,
            nested=self.var_nested.get(),
            auto_decode=self.var_auto_decode.get(),
            skip_broken=self.var_skip_broken.get(),
            context=40,
            top=int(self.ent_top.get() or 0),
            eid_filter=split(self.ent_eid.get()),
            since=self.ent_since.get().strip(),
            until=self.ent_until.get().strip(),
        )

    def _poll_events(self) -> None:
        """Drain the scanner event queue on the UI thread."""
        try:
            while True:
                event, payload = self._events.get_nowait()
                self._handle_event(event, payload)
        except Exception:  # noqa: BLE001 - queue.Empty and friends
            pass
        if self._scanning:
            self.root.after(80, self._poll_events)

    def _handle_event(self, event: str, payload: Any) -> None:
        """Dispatch one scanner event to the UI."""
        if event == EV_TOTAL:
            self.progress.configure(maximum=int(payload) or 1, value=0)
        elif event == EV_FILE_START:
            entry: FileEntry = payload
            # Unknown record count: pulse until the file completes.
            self.progress.configure(mode="indeterminate")
            self.progress.start(40)
            self.status_var.set(f"扫描中: {Path(entry.path).name}")
        elif event == EV_FILE_PROGRESS:
            entry = payload
            self._update_file_row(entry)
            self.status_var.set(
                f"扫描中: {Path(entry.path).name} | "
                f"已解析 {entry.records} 条, 命中 {entry.hits}"
            )
        elif event == EV_HIT:
            hit: RecordHit = payload
            self.hits.append(hit)
            ctx = hit.extracted or hit.context
            self.result_tree.insert(
                "", tk.END,
                values=(hit.event_time, hit.event_id, hit.channel,
                        ",".join(hit.matched_keywords), ctx,
                        Path(hit.file).name),
            )
        elif event == EV_FILE_DONE:
            entry = payload
            self._update_file_row(entry)
            self.progress.stop()
            self.progress.configure(mode="determinate")
            self.progress.step(1)
        elif event == EV_DONE:
            summary = payload
            self.progress.stop()
            self.progress.configure(mode="determinate")
            self.progress.configure(value=self.progress["maximum"])
            status = (
                f"完成: {summary['files']} 文件, {summary['records']} 记录, "
                f"{summary['hits']} 命中"
            )
            if not summary["hits"] and not self.var_nested.get():
                status += (
                    " | 提示: flag 可能藏在 Base64/Hex 编码中，"
                    "请勾选『嵌套解码匹配』后重扫"
                )
            self.status_var.set(status)
            self._finish_scan()
        elif event == EV_ERROR:
            self.status_var.set(f"错误: {payload}")

    def _update_file_row(self, entry: FileEntry) -> None:
        for existing in self.entries:
            if existing.path == entry.path:
                existing.records = entry.records
                existing.hits = entry.hits
                existing.error = entry.error
        self._append_file_row_refresh(entry)

    def _append_file_row_refresh(self, entry: FileEntry) -> None:
        """Refresh an existing file row (records/hits counters)."""
        name = Path(entry.path).name
        size_kb = f"{entry.size / 1024:.0f} KB" if entry.size else ""
        self.file_tree.item(
            entry.path,
            values=(entry.fmt, name, size_kb, entry.records, entry.hits,
                    entry.note or entry.error),
        )

    def _finish_scan(self) -> None:
        self._scanning = False
        self.scan_btn.state(["!disabled"])

    def _clear_results(self) -> None:
        self.hits.clear()
        self.result_tree.delete(*self.result_tree.get_children())
        self.detail.configure(state=tk.NORMAL)
        self.detail.delete("1.0", tk.END)
        self.detail.configure(state=tk.DISABLED)

    # -------------------------------------------------------------- detail

    def _on_select_result(self, _event: Any) -> None:
        selection = self.result_tree.selection()
        if not selection:
            return
        index = self.result_tree.index(selection[0])
        if index >= len(self.hits):
            return
        hit = self.hits[index]
        lines = [
            f"时间:   {hit.event_time}",
            f"事件ID: {hit.event_id}    通道: {hit.channel}",
            f"来源:   {hit.provider}    主机: {hit.computer}",
            f"文件:   {hit.file}  (Record #{hit.record_id})",
            f"关键词: {', '.join(hit.matched_keywords)}  "
            f"字段: {hit.match_field}  层: {hit.match_layer}",
        ]
        if hit.extracted:
            lines.append(f"提取:   {hit.extracted}")
        if hit.context:
            lines.append(f"片段:   {hit.context}")
        for span in hit.decoded:
            lines.append(f"解码:   {span}")
        lines.append("-" * 60)
        lines.append(hit.content)
        self.detail.configure(state=tk.NORMAL)
        self.detail.delete("1.0", tk.END)
        self.detail.insert(tk.END, "\n".join(lines))
        self.detail.configure(state=tk.DISABLED)

    def _copy_context(self) -> None:
        selection = self.result_tree.selection()
        if selection:
            hit = self.hits[self.result_tree.index(selection[0])]
            text = hit.extracted or hit.context
            self.root.clipboard_clear()
            self.root.clipboard_append(text)
            self.status_var.set("已复制命中片段")

    def _copy_content(self) -> None:
        selection = self.result_tree.selection()
        if selection:
            hit = self.hits[self.result_tree.index(selection[0])]
            self.root.clipboard_clear()
            self.root.clipboard_append(hit.content)
            self.status_var.set("已复制完整记录")

    # -------------------------------------------------------------- export

    def _export(self, fmt: str) -> None:
        if not self.hits:
            messagebox.showinfo("提示", "当前没有可导出的结果")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=f".{fmt}",
            filetypes=[(fmt.upper(), f"*.{fmt}")],
        )
        if not path:
            return
        try:
            out = exporter.export(self.hits, path, fmt)
        except (OSError, ValueError) as exc:
            messagebox.showerror("导出失败", str(exc))
            return
        self.status_var.set(f"已导出 {len(self.hits)} 条 -> {out}")


def run_gui() -> None:
    """Create the Tk root and start the main loop."""
    if _HAS_DND:
        root: tk.Tk = TkinterDnD.Tk()
    else:  # pragma: no cover - slim environments
        root = tk.Tk()
    FlagHunterApp(root)
    root.mainloop()


if __name__ == "__main__":  # pragma: no cover
    run_gui()
