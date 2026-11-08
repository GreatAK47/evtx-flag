"""Graphical interface - the primary interaction form (design doc 4.2).

Notebook layout with two tabs:

* ``Flag 检索`` tab   - the original CTF flag keyword hunt: option panel,
  file list, result table and record detail viewer.
* ``日志快速查找`` tab - one-click incident-response extractions (RDP
  logins, scheduled task changes, log clearing, ...) driven by the shared
  :mod:`evtx_flaghunter.quick_queries` registry.

Both tabs share the imported file list (top bar / drag & drop) and the
bottom status bar. Only one scan runs at a time; scanner events are routed
to whichever tab started the scan.
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
from evtx_flaghunter.quick_queries import (
    ALL_EIDS,
    QUICK_QUERIES,
    QuickQuery,
    match_scenarios,
    scenario_counts,
)
from evtx_flaghunter.eid_dict import eid_name
from evtx_flaghunter.extract import (
    aggregate_quick_stats,
    apply_sid_map,
    correlate_quick_hits,
    eid_histogram,
    postprocess_powershell,
)
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

_TAB_FLAG = "flag"
_TAB_QUICK = "quick"


def _attach_scrollbars(
    container: ttk.Frame, tree: ttk.Treeview, horizontal: bool = True
) -> None:
    """Pack draggable scrollbars around *tree* (vertical always, optional X)."""
    ysb = ttk.Scrollbar(container, orient=tk.VERTICAL, command=tree.yview)
    tree.configure(yscrollcommand=ysb.set)
    ysb.pack(side=tk.RIGHT, fill=tk.Y)
    if horizontal:
        xsb = ttk.Scrollbar(
            container, orient=tk.HORIZONTAL, command=tree.xview
        )
        tree.configure(xscrollcommand=xsb.set)
        xsb.pack(side=tk.BOTTOM, fill=tk.X)
    tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)


class FlagHunterApp:
    """Main application window (two-tab notebook)."""

    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.entries: list[FileEntry] = []
        self.hits: list[RecordHit] = []  # flag tab results
        self.quick_hits: list[RecordHit] = []  # quick tab results
        self._events: Any = None
        self._scanning = False
        self._scan_kind = _TAB_FLAG  # routes events to the owning tab
        self._scanner: Scanner | None = None  # kept for sid_map after EV_DONE
        self._quick_all = False  # True while the emergency all-scan runs
        self._temp_dirs: list[str] = []
        self._build_ui()
        # Only a TkinterDnD-enabled root supports drop targets; a plain
        # tk.Tk (e.g. in tests) must degrade gracefully to buttons/paste.
        if _HAS_DND and hasattr(root, "drop_target_register"):
            root.drop_target_register(DND_FILES)
            root.dnd_bind("<<Drop>>", self._on_drop)

    # ------------------------------------------------------------------ UI

    def _build_ui(self) -> None:
        """Create every widget (design doc layout sketch, section 4.2)."""
        self.root.title("EVTX-FlagHunter - CTF 事件日志 Flag 检索")
        self.root.geometry("1100x720")
        self.root.minsize(900, 600)

        # Top bar: shared import + flag preset + flag scan trigger ---------
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
            top, text="\u25b6 开始Flag检索", command=self._start_scan
        )
        self.scan_btn.pack(side=tk.LEFT, padx=12)

        # Tabs --------------------------------------------------------------
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True)
        self._build_flag_tab()
        self._build_quick_tab()

        # Status bar (shared by both tabs) ----------------------------------
        status = ttk.Frame(self.root, padding=4)
        status.pack(fill=tk.X)
        self.progress = ttk.Progressbar(status, mode="determinate", length=260)
        self.progress.pack(side=tk.LEFT)
        self.status_var = tk.StringVar(value="拖入 .evtx 文件或文件夹开始")
        ttk.Label(status, textvariable=self.status_var).pack(side=tk.LEFT, padx=8)

    # -- flag tab ----------------------------------------------------------

    def _build_flag_tab(self) -> None:
        """Original keyword-hunt layout: options + files/results/detail."""
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="Flag 检索")
        body = ttk.Frame(tab)
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
        ttk.Label(left, text="事件ID 过滤 (预过滤):").pack(anchor=tk.W)
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
        _attach_scrollbars(file_frame, self.file_tree)
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
        _attach_scrollbars(result_frame, self.result_tree)
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
        ttk.Button(btns, text="导出 JSON", command=lambda: self._export(_TAB_FLAG, "json")).pack(
            side=tk.RIGHT
        )
        ttk.Button(btns, text="导出 CSV", command=lambda: self._export(_TAB_FLAG, "csv")).pack(
            side=tk.RIGHT, padx=4
        )
        self.detail = self._make_detail_text(detail_frame)
        right.add(detail_frame, weight=3)

    # -- quick query tab ---------------------------------------------------

    def _build_quick_tab(self) -> None:
        """One-click incident-response extraction tab."""
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="日志快速查找 (未完工·慎用)")
        body = ttk.Frame(tab)
        body.pack(fill=tk.BOTH, expand=True)

        # Left: scenario picker -------------------------------------------
        left = ttk.LabelFrame(body, text="快速查询场景 (一键提取)", padding=8)
        left.pack(side=tk.LEFT, fill=tk.Y, padx=6, pady=4)

        self._quick_map: dict[str, QuickQuery] = {
            f"{q.label} ({q.name})": q for q in QUICK_QUERIES.values()
        }
        choices = list(self._quick_map)
        self.quick_var = tk.StringVar(value=choices[0])
        combo = ttk.Combobox(
            left,
            textvariable=self.quick_var,
            values=choices,
            width=28,
            state="readonly",
        )
        combo.pack(fill=tk.X, pady=2)
        combo.bind("<<ComboboxSelected>>", self._on_quick_selected)

        # Offline smart search: digits -> EID lookup, words -> scenario.
        search_row = ttk.Frame(left)
        search_row.pack(fill=tk.X, pady=(8, 2))
        self.q_ent_search = ttk.Entry(search_row)
        self.q_ent_search.pack(side=tk.LEFT, fill=tk.X, expand=True)
        self.q_ent_search.bind("<Return>", lambda _e: self._smart_search())
        ttk.Button(
            search_row, text="🔎", width=3, command=self._smart_search,
        ).pack(side=tk.LEFT, padx=2)

        self.quick_desc_var = tk.StringVar()
        ttk.Label(
            left, textvariable=self.quick_desc_var, wraplength=200,
            foreground="#555555", justify=tk.LEFT,
        ).pack(fill=tk.X, pady=4)
        self._on_quick_selected()

        ttk.Separator(left).pack(fill=tk.X, pady=6)
        ttk.Label(left, text="补充事件ID (可选, 空格分隔):").pack(anchor=tk.W)
        self.q_ent_eid = ttk.Entry(left, width=28)
        self.q_ent_eid.pack(fill=tk.X, pady=2)
        ttk.Label(left, text="时间范围 since (UTC, 可选):").pack(anchor=tk.W, pady=(6, 0))
        self.q_ent_since = ttk.Entry(left, width=28)
        self.q_ent_since.pack(fill=tk.X, pady=2)
        ttk.Label(left, text="时间范围 until (UTC, 可选):").pack(anchor=tk.W, pady=(6, 0))
        self.q_ent_until = ttk.Entry(left, width=28)
        self.q_ent_until.pack(fill=tk.X, pady=2)
        ttk.Label(left, text="最多输出条数:").pack(anchor=tk.W, pady=(6, 0))
        self.q_sort_time = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            left, text="完成后按时间排序（时间线视图）",
            variable=self.q_sort_time,
        ).pack(anchor=tk.W, pady=(6, 0))
        self.q_ent_top = ttk.Spinbox(left, from_=0, to=100000, width=10)
        self.q_ent_top.set(0)
        self.q_ent_top.pack(anchor=tk.W, pady=2)

        self.quick_btn = ttk.Button(
            left, text="\u26a1 一键提取", command=self._run_quick_query
        )
        self.quick_btn.pack(fill=tk.X, pady=(10, 2))
        self.quick_all_btn = ttk.Button(
            left, text="\U0001F691 应急全扫描 (不知道ID就点这个)",
            command=self._run_quick_all,
        )
        self.quick_all_btn.pack(fill=tk.X, pady=(2, 2))

        # Right: results / detail ------------------------------------------
        right = ttk.PanedWindow(body, orient=tk.VERTICAL)
        right.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        result_frame = ttk.LabelFrame(
            right, text="提取结果 (双击查看详情)", padding=4
        )
        self.q_result_tree = ttk.Treeview(
            result_frame,
            columns=("time", "eid", "summary", "sus", "file"),
            show="headings",
            height=10,
        )
        for col, text, width in (
            ("time", "时间 (UTC)", 160),
            ("eid", "事件ID", 70),
            ("summary", "结论 / 用户名", 380),
            ("sus", "可疑原因", 200),
            ("file", "文件", 140),
        ):
            self.q_result_tree.heading(col, text=text)
            self.q_result_tree.column(col, width=width, anchor=tk.W)
        self.q_result_tree.tag_configure(
            "suspicious", foreground="#c00000"
        )
        _attach_scrollbars(result_frame, self.q_result_tree)
        self.q_result_tree.bind(
            "<<TreeviewSelect>>", self._on_select_quick_result
        )
        right.add(result_frame, weight=3)

        detail_frame = ttk.LabelFrame(right, text="记录详情", padding=4)
        btns = ttk.Frame(detail_frame)
        btns.pack(fill=tk.X)
        ttk.Button(
            btns, text="复制命中片段", command=self._copy_quick_context
        ).pack(side=tk.LEFT)
        ttk.Button(
            btns, text="复制完整记录", command=self._copy_quick_content
        ).pack(side=tk.LEFT, padx=4)
        ttk.Button(
            btns, text="导出 JSON", command=lambda: self._export(_TAB_QUICK, "json")
        ).pack(side=tk.RIGHT)
        ttk.Button(
            btns, text="导出 CSV", command=lambda: self._export(_TAB_QUICK, "csv")
        ).pack(side=tk.RIGHT, padx=4)
        self.q_detail = self._make_detail_text(detail_frame)
        right.add(detail_frame, weight=3)

    @staticmethod
    def _make_detail_text(parent: ttk.Frame) -> tk.Text:
        """Consolas detail viewer with a vertical scrollbar."""
        text = tk.Text(
            parent, height=8, wrap=tk.NONE, state=tk.DISABLED,
            font=("Consolas", 9),
        )
        ysb = ttk.Scrollbar(parent, orient=tk.VERTICAL, command=text.yview)
        text.configure(yscrollcommand=ysb.set)
        text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        ysb.pack(side=tk.RIGHT, fill=tk.Y)
        return text

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

    def _on_quick_selected(self, _event: Any = None) -> None:
        """Show the selected quick-query description under the combo box."""
        query = self._quick_map[self.quick_var.get()]
        self.quick_desc_var.set(query.description)

    def _quick_config(self, eids: list[str]) -> ScanConfig:
        """Build a quick-tab ScanConfig for the given event IDs."""
        split = lambda text: [t for t in text.replace(",", " ").split() if t]
        return ScanConfig(
            paths=[entry.path for entry in self.entries],
            eid_filter=list(dict.fromkeys(eids + split(self.q_ent_eid.get()))),
            eid_match=True,  # EID is the match criterion, not a pre-filter
            auto_decode=False,  # pure EID extraction needs no decoding
            nested=False,
            context=60,
            top=int(self.q_ent_top.get() or 0),
            since=self.q_ent_since.get().strip(),
            until=self.q_ent_until.get().strip(),
        )

    def _run_quick_query(self) -> None:
        """One-click DFIR extraction from the quick tab."""
        query = self._quick_map[self.quick_var.get()]
        self._quick_all = False
        hint = (
            f"[{query.label}] {query.description}"
            if query.description else ""
        )
        self.status_var.set(hint)
        self._launch_scan(self._quick_config(list(query.eids)), _TAB_QUICK)

    def _run_quick_all(self) -> None:
        """Emergency mode: union of every scenario in a single pass."""
        if not self.entries:
            messagebox.showinfo("提示", "请先拖入或添加 .evtx 文件")
            return
        self._quick_all = True
        self.status_var.set("应急模式：一次扫描覆盖全部预设场景")
        self._launch_scan(self._quick_config(list(ALL_EIDS)), _TAB_QUICK)

    def _smart_search(self) -> None:
        """Offline three-way lookup, no model needed (设计方向 D).

        1. Pure digits -> direct event-ID scan.
        2. Scenario dictionary hit -> select the scenario and scan.
        3. Otherwise -> jump to the flag tab and run a full-text search.
        """
        text = self.q_ent_search.get().strip()
        if not text:
            return
        if not self.entries:
            messagebox.showinfo("提示", "请先拖入或添加 .evtx 文件")
            return
        if text.isdigit():
            self.status_var.set(
                f"按事件ID {text} 直查"
                f"（{eid_name(text) or '词典未收录，将展示原始记录'}）"
            )
            self._quick_all = False
            self._launch_scan(self._quick_config([text]), _TAB_QUICK)
            return
        matches = match_scenarios(text)
        if matches:
            query = matches[0]
            self.quick_var.set(f"{query.label} ({query.name})")
            self._on_quick_selected()
            self._run_quick_query()
            return
        self.ent_keywords.delete(0, tk.END)
        self.ent_keywords.insert(0, text)
        self.notebook.select(0)
        self._start_scan()

    def _start_scan(self) -> None:
        """One-click flag scan entry point (zero configuration required)."""
        if not self.entries:
            messagebox.showinfo("提示", "请先拖入或添加 .evtx 文件")
            return
        self._launch_scan(self._build_config(), _TAB_FLAG)

    def _build_config(self) -> ScanConfig:
        """Collect flag-tab widget state into a ScanConfig."""
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

    def _launch_scan(self, config: ScanConfig, kind: str) -> None:
        """Start one scan and route its events to the requesting tab."""
        if self._scanning:
            return
        self._scan_kind = kind
        self._clear_results(kind)
        self._scanning = True
        self.scan_btn.state(["disabled"])
        self.quick_btn.state(["disabled"])
        self.progress.configure(value=0, mode="determinate")
        self.status_var.set("扫描中...")

        scanner = Scanner(config)
        self._scanner = scanner  # kept for sid_map after EV_DONE
        self._events, _thread = scanner.start_async()
        self.root.after(80, self._poll_events)

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
            if self._scan_kind == _TAB_QUICK:
                self._append_quick_hit(hit)
            else:
                self._append_flag_hit(hit)
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
            if (
                not summary["hits"]
                and self._scan_kind == _TAB_FLAG
                and not self.var_nested.get()
            ):
                status += (
                    " | 提示: flag 可能藏在 Base64/Hex 编码中，"
                    "请勾选『嵌套解码匹配』后重扫"
                )
            self.status_var.set(status)
            if self._scan_kind == _TAB_QUICK:
                self._finalize_quick_hits()
            self._finish_scan()
        elif event == EV_ERROR:
            self.status_var.set(f"错误: {payload}")

    def _append_flag_hit(self, hit: RecordHit) -> None:
        """Add one hit to the flag tab result table."""
        self.hits.append(hit)
        ctx = hit.extracted or hit.context
        self.result_tree.insert(
            "", tk.END,
            values=(hit.event_time, hit.event_id, hit.channel,
                    ",".join(hit.matched_keywords), ctx,
                    Path(hit.file).name),
        )

    def _append_quick_hit(self, hit: RecordHit) -> None:
        """Add one hit to the quick tab result table (conclusion-first)."""
        self.quick_hits.append(hit)
        self._render_quick_row(hit)

    def _render_quick_row(self, hit: RecordHit) -> None:
        """Insert one hit row into the quick tab table."""
        summary = hit.summary or hit.extracted or hit.context
        sus = "⚠ " + "; ".join(hit.suspicious) if hit.suspicious else ""
        self.q_result_tree.insert(
            "", tk.END,
            values=(hit.event_time, hit.event_id, summary, sus,
                    Path(hit.file).name),
            tags=("suspicious",) if hit.suspicious else (),
        )

    def _finalize_quick_hits(self) -> None:
        """Post-process quick hits once EV_DONE fires (P1).

        Reassembles fragmented 4104 script blocks, drops repeat noise,
        resolves SIDs to account names, then refreshes the table and shows
        per-key aggregation stats in the detail pane.
        """
        self.quick_hits = postprocess_powershell(self.quick_hits)
        sid_map = getattr(self._scanner, "sid_map", {})
        apply_sid_map(self.quick_hits, sid_map)
        if self.q_sort_time.get():
            self.quick_hits.sort(
                key=lambda h: (h.event_time, h.file, h.record_id)
            )
        self.q_result_tree.delete(*self.q_result_tree.get_children())
        for hit in self.quick_hits:
            self._render_quick_row(hit)
        sections: list[str] = []
        hist = eid_histogram(
            dict(getattr(self._scanner, "eid_counts", {}) or {})
        )
        if hist:
            sections.append("[事件ID分布]（⚡=稀有事件，攻击动作通常在此）")
            sections.extend(hist)
        if self._quick_all:
            counts = scenario_counts(self.quick_hits)
            if counts:
                sections.append("[场景命中]")
                sections.extend(counts)
        stats = aggregate_quick_stats(self.quick_hits)
        corr = correlate_quick_hits(self.quick_hits)
        if corr:
            stats.append("[关联分析]")
            stats.extend(corr)
        if stats:
            sections.append("[聚合统计]")
            sections.extend(stats)
        if sections:
            self._set_text(self.q_detail, "\n".join(sections) + "\n")

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
        self.quick_btn.state(["!disabled"])

    def _clear_results(self, kind: str) -> None:
        """Clear the result widgets of *kind* before a new scan."""
        if kind == _TAB_QUICK:
            self.quick_hits.clear()
            self.q_result_tree.delete(*self.q_result_tree.get_children())
            self._set_text(self.q_detail, "")
            return
        self.hits.clear()
        self.result_tree.delete(*self.result_tree.get_children())
        self._set_text(self.detail, "")

    @staticmethod
    def _set_text(widget: tk.Text, content: str) -> None:
        widget.configure(state=tk.NORMAL)
        widget.delete("1.0", tk.END)
        widget.insert(tk.END, content)
        widget.configure(state=tk.DISABLED)

    # -------------------------------------------------------------- detail

    @staticmethod
    def _render_hit_lines(hit: RecordHit) -> list[str]:
        """Human-readable detail lines shared by both tabs."""
        lines = [
            f"时间:   {hit.event_time}",
            f"事件ID: {hit.event_id}    通道: {hit.channel}",
            f"来源:   {hit.provider}    主机: {hit.computer}",
            f"文件:   {hit.file}  (Record #{hit.record_id})",
            f"关键词: {', '.join(hit.matched_keywords)}  "
            f"字段: {hit.match_field}  层: {hit.match_layer}",
        ]
        if hit.summary:
            lines.append(f"结论:   {hit.summary}")
        if hit.suspicious:
            lines.append(f"可疑:   {'; '.join(hit.suspicious)}")
        if hit.fields:
            pairs = "  ".join(
                f"{key}={value}" for key, value in hit.fields.items() if value
            )
            lines.append(f"字段:   {pairs}")
        if hit.extracted:
            lines.append(f"提取:   {hit.extracted}")
        if hit.context:
            lines.append(f"片段:   {hit.context}")
        for span in hit.decoded:
            lines.append(f"解码:   {span}")
        lines.append("-" * 60)
        lines.append(hit.content)
        return lines

    def _show_hit(self, widget: tk.Text, hit: RecordHit) -> None:
        self._set_text(widget, "\n".join(self._render_hit_lines(hit)))

    def _on_select_result(self, _event: Any) -> None:
        selection = self.result_tree.selection()
        if not selection:
            return
        index = self.result_tree.index(selection[0])
        if index < len(self.hits):
            self._show_hit(self.detail, self.hits[index])

    def _on_select_quick_result(self, _event: Any) -> None:
        selection = self.q_result_tree.selection()
        if not selection:
            return
        index = self.q_result_tree.index(selection[0])
        if index < len(self.quick_hits):
            self._show_hit(self.q_detail, self.quick_hits[index])

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

    def _copy_quick_context(self) -> None:
        selection = self.q_result_tree.selection()
        if selection:
            hit = self.quick_hits[self.q_result_tree.index(selection[0])]
            text = hit.summary or hit.extracted or hit.context
            self.root.clipboard_clear()
            self.root.clipboard_append(text)
            self.status_var.set("已复制结论" if hit.summary else "已复制命中片段")

    def _copy_quick_content(self) -> None:
        selection = self.q_result_tree.selection()
        if selection:
            hit = self.quick_hits[self.q_result_tree.index(selection[0])]
            self.root.clipboard_clear()
            self.root.clipboard_append(hit.content)
            self.status_var.set("已复制完整记录")

    # -------------------------------------------------------------- export

    def _export(self, kind: str, fmt: str) -> None:
        hits = self.quick_hits if kind == _TAB_QUICK else self.hits
        if not hits:
            messagebox.showinfo("提示", "当前没有可导出的结果")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=f".{fmt}",
            filetypes=[(fmt.upper(), f"*.{fmt}")],
        )
        if not path:
            return
        try:
            out = exporter.export(hits, path, fmt)
        except (OSError, ValueError) as exc:
            messagebox.showerror("导出失败", str(exc))
            return
        self.status_var.set(f"已导出 {len(hits)} 条 -> {out}")


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
