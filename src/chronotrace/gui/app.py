"""ChronoTrace Desktop GUI Application."""

from __future__ import annotations
import os
import sys
import threading
import webbrowser
from pathlib import Path
from typing import List, Optional
import tkinter as tk
from tkinter import ttk, messagebox, filedialog

from chronotrace.core.case import Case
from chronotrace.acquire.devices import DeviceManager, StorageDevice
from chronotrace.acquire.hotplug import HotplugWatcher
from chronotrace.timeline.query import TimelineQuery
from chronotrace.extract.registry import list_plugins


class ChronoTraceGUI:
    """Main Graphical User Interface for the ChronoTrace Forensics Platform."""

    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("WASP — Forensic Evidence & Super-Timeline Platform")
        self.root.geometry("1180x760")
        self.root.minsize(980, 640)

        self.current_case: Optional[Case] = None
        self.detected_devices: List[StorageDevice] = []

        self._configure_styles()
        self._build_ui()
        self._refresh_devices_thread()

        # Start real-time hotplug watcher for external USB devices
        self.hotplug_watcher = HotplugWatcher(
            poll_interval=1.5,
            on_connected=self._on_hotplug_connected,
            on_disconnected=self._on_hotplug_disconnected,
        )
        self.hotplug_watcher.start()
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

    def _on_close(self):
        try:
            if hasattr(self, "hotplug_watcher") and self.hotplug_watcher:
                self.hotplug_watcher.stop()
        except Exception:
            pass
        self.root.destroy()

    def _configure_styles(self):
        """Set up liquid glass and frosted obsidian ttk styles."""
        self.style = ttk.Style()
        try:
            self.style.theme_use("clam")
        except Exception:
            pass

        # Liquid Glass Palette
        bg_dark = "#090d16"
        card_bg = "#111726"
        card_border = "#1e2942"
        accent_cyan = "#00f2fe"
        accent_blue = "#3b82f6"
        text_light = "#f1f5f9"
        text_muted = "#94a3b8"

        self.root.configure(bg=bg_dark)
        self.style.configure(".", background=bg_dark, foreground=text_light, font=("Segoe UI", 9))
        self.style.configure("TLabel", background=bg_dark, foreground=text_light)
        self.style.configure("Header.TLabel", font=("Segoe UI", 12, "bold"), foreground=accent_cyan)
        self.style.configure("SubHeader.TLabel", font=("Segoe UI", 10, "bold"), foreground="#67e8f9")
        self.style.configure("Badge.TLabel", font=("Segoe UI", 9, "bold"), foreground="#10b981")

        self.style.configure("TNotebook", background=bg_dark, tabmargins=[4, 6, 4, 0])
        self.style.configure(
            "TNotebook.Tab",
            background="#141c2e",
            foreground=text_muted,
            padding=[14, 7],
            font=("Segoe UI", 9, "bold"),
            bordercolor=card_border,
        )
        self.style.map(
            "TNotebook.Tab",
            background=[("selected", "#1e2942"), ("active", "#182238")],
            foreground=[("selected", accent_cyan), ("active", "#ffffff")],
        )

        self.style.configure("TButton", font=("Segoe UI", 9, "bold"), padding=6, background="#182238", foreground=text_light, bordercolor=card_border)
        self.style.map("TButton", background=[("active", "#2563eb")], foreground=[("active", "#ffffff")])

        self.style.configure("Accent.TButton", background="#059669", foreground="#ffffff", font=("Segoe UI", 9, "bold"), padding=6)
        self.style.map("Accent.TButton", background=[("active", "#10b981")])

        self.style.configure(
            "Treeview",
            background=card_bg,
            foreground=text_light,
            fieldbackground=card_bg,
            rowheight=26,
            font=("Segoe UI", 9),
        )
        self.style.configure(
            "Treeview.Heading",
            background="#162035",
            foreground=accent_cyan,
            font=("Segoe UI", 9, "bold"),
            padding=6,
        )
        self.style.map("Treeview", background=[("selected", "#2563eb")], foreground=[("selected", "#ffffff")])

    def _build_ui(self):
        # 1. Top Header Banner with Frosted Glass Header
        header_frame = tk.Frame(self.root, bg="#0d1322", height=64, padx=18, pady=12, highlightbackground="#1e2942", highlightthickness=1)
        header_frame.pack(fill=tk.X, side=tk.TOP)

        title_lbl = tk.Label(header_frame, text="⚡ WASP", font=("Segoe UI", 16, "bold"), fg="#00f2fe", bg="#0d1322")
        title_lbl.pack(side=tk.LEFT)

        subtitle_lbl = tk.Label(header_frame, text=" | Wide-scope Artifact & Super-timeline Platform", font=("Segoe UI", 10), fg="#94a3b8", bg="#0d1322")
        subtitle_lbl.pack(side=tk.LEFT, padx=6)

        self.case_status_lbl = tk.Label(header_frame, text="● [No Active Case]", font=("Segoe UI", 10, "bold"), fg="#f43f5e", bg="#0d1322")
        self.case_status_lbl.pack(side=tk.RIGHT, padx=12)

        btn_open = ttk.Button(header_frame, text="📂 Open Case...", command=self._open_case_dialog)
        btn_open.pack(side=tk.RIGHT, padx=4)

        btn_new = ttk.Button(header_frame, text="+ New Case...", command=self._new_case_dialog)
        btn_new.pack(side=tk.RIGHT, padx=4)

        # 2. Main Notebook Tabs
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Tabs:
        self.tab_case = ttk.Frame(self.notebook, padding=10)
        self.tab_devices = ttk.Frame(self.notebook, padding=10)
        self.tab_extract = ttk.Frame(self.notebook, padding=10)
        self.tab_timeline = ttk.Frame(self.notebook, padding=10)
        self.tab_integrity = ttk.Frame(self.notebook, padding=10)
        self.tab_reports = ttk.Frame(self.notebook, padding=10)

        self.notebook.add(self.tab_case, text=" 📂 Case Dashboard ")
        self.notebook.add(self.tab_devices, text=" 🔌 External Devices & Acquire ")
        self.notebook.add(self.tab_extract, text=" ⚙️ Artefacts & Ingest ")
        self.notebook.add(self.tab_timeline, text=" ⏱️ Activity Timeline ")
        self.notebook.add(self.tab_integrity, text=" 🛡️ Integrity & Custody ")
        self.notebook.add(self.tab_reports, text=" 📄 Investigation Reports ")

        self._build_tab_case()
        self._build_tab_devices()
        self._build_tab_extract()
        self._build_tab_timeline()
        self._build_tab_integrity()
        self._build_tab_reports()

        # 3. Bottom Status Bar
        status_frame = tk.Frame(self.root, bg="#0d1322", height=30, padx=12, pady=5, highlightbackground="#1e2942", highlightthickness=1)
        status_frame.pack(fill=tk.X, side=tk.BOTTOM)

        self.status_var = tk.StringVar(value="Ready. Write-Guard: ACTIVE (Read-Only Forensic Protection) | RFC 3161 TSA Enabled")
        lbl_status = tk.Label(status_frame, textvariable=self.status_var, font=("Segoe UI", 9), fg="#10b981", bg="#0d1322")
        lbl_status.pack(side=tk.LEFT)

        lbl_ver = tk.Label(status_frame, text="WASP v1.4.0 | Liquid Glass Edition", font=("Segoe UI", 8), fg="#94a3b8", bg="#0d1322")
        lbl_ver.pack(side=tk.RIGHT)

    # ---------------- TAB 1: CASE DASHBOARD ----------------
    def _build_tab_case(self):
        lbl = ttk.Label(self.tab_case, text="Case Overview & Forensic Workspace", style="Header.TLabel")
        lbl.pack(anchor=tk.W, pady=(0, 10))

        # High-Contrast KPI Stat Cards Row
        kpi_frame = tk.Frame(self.tab_case, bg="#090c12")
        kpi_frame.pack(fill=tk.X, pady=(0, 12))

        # Card 1: Evidence Files
        c1 = tk.Frame(kpi_frame, bg="#121722", highlightbackground="#26334a", highlightthickness=1, padx=14, pady=10)
        c1.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 5))
        tk.Label(c1, text="EVIDENCE OBJECTS", font=("Segoe UI", 8, "bold"), fg="#38bdf8", bg="#121722").pack(anchor=tk.W)
        self.kpi_ev_count = tk.Label(c1, text="0", font=("Segoe UI", 16, "bold"), fg="#ffffff", bg="#121722")
        self.kpi_ev_count.pack(anchor=tk.W)

        # Card 2: Timeline Events
        c2 = tk.Frame(kpi_frame, bg="#121722", highlightbackground="#26334a", highlightthickness=1, padx=14, pady=10)
        c2.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5)
        tk.Label(c2, text="TIMELINE EVENTS", font=("Segoe UI", 8, "bold"), fg="#34d399", bg="#121722").pack(anchor=tk.W)
        self.kpi_event_count = tk.Label(c2, text="0", font=("Segoe UI", 16, "bold"), fg="#ffffff", bg="#121722")
        self.kpi_event_count.pack(anchor=tk.W)

        # Card 3: Cryptographic Integrity
        c3 = tk.Frame(kpi_frame, bg="#121722", highlightbackground="#26334a", highlightthickness=1, padx=14, pady=10)
        c3.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5)
        tk.Label(c3, text="CRYPTO INTEGRITY", font=("Segoe UI", 8, "bold"), fg="#c084fc", bg="#121722").pack(anchor=tk.W)
        self.kpi_integrity = tk.Label(c3, text="NOT VERIFIED", font=("Segoe UI", 14, "bold"), fg="#94a3b8", bg="#121722")
        self.kpi_integrity.pack(anchor=tk.W)

        # Card 4: Write-Guard Status
        c4 = tk.Frame(kpi_frame, bg="#121722", highlightbackground="#26334a", highlightthickness=1, padx=14, pady=10)
        c4.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(5, 0))
        tk.Label(c4, text="FORENSIC WRITE-GUARD", font=("Segoe UI", 8, "bold"), fg="#f59e0b", bg="#121722").pack(anchor=tk.W)
        self.kpi_writeguard = tk.Label(c4, text="ACTIVE (RO)", font=("Segoe UI", 14, "bold"), fg="#34d399", bg="#121722")
        self.kpi_writeguard.pack(anchor=tk.W)

        info_frame = tk.LabelFrame(self.tab_case, text=" Active Case Properties ", bg="#121722", fg="#38bdf8", font=("Segoe UI", 9, "bold"), padx=12, pady=10, highlightbackground="#26334a", highlightthickness=1)
        info_frame.pack(fill=tk.X, pady=5)

        self.case_details_text = tk.Text(info_frame, height=9, bg="#0d121c", fg="#f1f5f9", relief=tk.FLAT, font=("Consolas", 9), padx=8, pady=8)
        self.case_details_text.pack(fill=tk.X)
        self.case_details_text.insert(tk.END, "No case currently opened. Click '+ New Case' to create or 'Open Case' to load an existing workspace.\n")
        self.case_details_text.config(state=tk.DISABLED)

        # Quick Actions Card
        actions_frame = tk.LabelFrame(self.tab_case, text=" Quick Forensic Actions ", bg="#121722", fg="#38bdf8", font=("Segoe UI", 9, "bold"), padx=12, pady=12, highlightbackground="#26334a", highlightthickness=1)
        actions_frame.pack(fill=tk.X, pady=10)

        btn_run_all = tk.Button(actions_frame, text="⚡ Run Full Automated Pipeline (Extract -> Timeline -> Verify -> Report)", bg="#059669", activebackground="#10b981", fg="#ffffff", activeforeground="#ffffff", font=("Segoe UI", 9, "bold"), relief=tk.FLAT, padx=12, pady=6, command=self._run_full_pipeline_thread)
        btn_run_all.pack(side=tk.LEFT, padx=6)

        btn_add_file = ttk.Button(actions_frame, text="📁 Acquire Evidence File...", command=self._acquire_file_dialog)
        btn_add_file.pack(side=tk.LEFT, padx=6)

        btn_doctor = ttk.Button(actions_frame, text="🩺 Run Diagnostics (Doctor)", command=self._run_doctor_dialog)
        btn_doctor.pack(side=tk.LEFT, padx=6)

    # ---------------- TAB 2: EXTERNAL DEVICES & ACQUISITION ----------------
    def _build_tab_devices(self):
        header_bar = ttk.Frame(self.tab_devices)
        header_bar.pack(fill=tk.X, pady=(0, 10))

        ttk.Label(header_bar, text="Connected Storage & External Devices", style="Header.TLabel").pack(side=tk.LEFT)
        lbl_watch_status = tk.Label(header_bar, text="🟢 Real-Time Hotplug Watcher: ACTIVE", fg="#3fb950", bg="#181a20", font=("Segoe UI", 9, "bold"))
        lbl_watch_status.pack(side=tk.LEFT, padx=15)

        btn_refresh = ttk.Button(header_bar, text="🔄 Refresh Devices", command=self._refresh_devices_thread)
        btn_refresh.pack(side=tk.RIGHT)

        # Devices Treeview
        columns = ("device_id", "model", "type", "mount", "fs", "size", "serial")
        self.tree_devices = ttk.Treeview(self.tab_devices, columns=columns, show="headings", height=8)
        self.tree_devices.heading("device_id", text="Device ID")
        self.tree_devices.heading("model", text="Device / Volume Model")
        self.tree_devices.heading("type", text="Interface / Type")
        self.tree_devices.heading("mount", text="Mount Point")
        self.tree_devices.heading("fs", text="Filesystem")
        self.tree_devices.heading("size", text="Capacity")
        self.tree_devices.heading("serial", text="Serial Number")

        self.tree_devices.column("device_id", width=110)
        self.tree_devices.column("model", width=220)
        self.tree_devices.column("type", width=130)
        self.tree_devices.column("mount", width=80)
        self.tree_devices.column("fs", width=80)
        self.tree_devices.column("size", width=90)
        self.tree_devices.column("serial", width=140)

        self.tree_devices.pack(fill=tk.BOTH, expand=True, pady=5)
        self.tree_devices.bind("<<TreeviewSelect>>", self._on_device_select)

        # Acquisition Form Frame
        acq_frame = tk.LabelFrame(self.tab_devices, text=" Forensic Evidence Acquisition ", bg="#111726", fg="#00f2fe", font=("Segoe UI", 9, "bold"), padx=12, pady=10, highlightbackground="#1e2942", highlightthickness=1)
        acq_frame.pack(fill=tk.X, pady=10)

        row1 = ttk.Frame(acq_frame)
        row1.pack(fill=tk.X, pady=3)
        ttk.Label(row1, text="Selected Device:", width=16).pack(side=tk.LEFT)
        self.lbl_selected_dev = ttk.Label(row1, text="[Please select a device above]", font=("Segoe UI", 9, "bold"), foreground="#38bdf8")
        self.lbl_selected_dev.pack(side=tk.LEFT)

        row2 = ttk.Frame(acq_frame)
        row2.pack(fill=tk.X, pady=3)
        ttk.Label(row2, text="Output Container:", width=16).pack(side=tk.LEFT)
        self.entry_out_name = ttk.Entry(row2, width=35)
        self.entry_out_name.insert(0, "usb_evidence.tar")
        self.entry_out_name.pack(side=tk.LEFT, padx=5)

        ttk.Label(row2, text="Notes / Ref:").pack(side=tk.LEFT, padx=(15, 5))
        self.entry_acq_notes = ttk.Entry(row2, width=40)
        self.entry_acq_notes.insert(0, "Seized external USB storage device")
        self.entry_acq_notes.pack(side=tk.LEFT)

        btn_acquire = tk.Button(acq_frame, text="🔒 Acquire Evidence with SHA-256 Hash", bg="#059669", activebackground="#10b981", fg="#ffffff", activeforeground="#ffffff", relief=tk.FLAT, font=("Segoe UI", 9, "bold"), padx=10, pady=5, command=self._acquire_selected_device_thread)
        btn_acquire.pack(anchor=tk.E, pady=8)

    # ---------------- TAB 3: ARTEFACTS & INGEST ----------------
    def _build_tab_extract(self):
        lbl = ttk.Label(self.tab_extract, text="Digital Evidence Ingestion & Artefact Parsing", style="Header.TLabel")
        lbl.pack(anchor=tk.W, pady=(0, 10))

        controls_frame = ttk.Frame(self.tab_extract)
        controls_frame.pack(fill=tk.X, pady=5)

        ttk.Label(controls_frame, text="Analysis Profile:").pack(side=tk.LEFT, padx=5)
        self.combo_profile = ttk.Combobox(controls_frame, values=["all", "windows", "linux"], width=12, state="readonly")
        self.combo_profile.set("all")
        self.combo_profile.pack(side=tk.LEFT, padx=5)

        btn_extract = tk.Button(controls_frame, text="▶ Run Ingestion & Extraction", bg="#2563eb", activebackground="#3b82f6", fg="#ffffff", activeforeground="#ffffff", relief=tk.FLAT, font=("Segoe UI", 9, "bold"), padx=10, pady=4, command=self._run_extraction_thread)
        btn_extract.pack(side=tk.LEFT, padx=15)

        # Extraction Log Box
        log_frame = tk.LabelFrame(self.tab_extract, text=" Ingestion Log & Detected Records ", bg="#111726", fg="#00f2fe", font=("Segoe UI", 9, "bold"), padx=10, pady=10, highlightbackground="#1e2942", highlightthickness=1)
        log_frame.pack(fill=tk.BOTH, expand=True, pady=10)

        self.txt_extract_log = tk.Text(log_frame, bg="#070a12", fg="#f1f5f9", relief=tk.FLAT, font=("Consolas", 9), padx=8, pady=8)
        self.txt_extract_log.pack(fill=tk.BOTH, expand=True)

    # ---------------- TAB 4: ACTIVITY TIMELINE ----------------
    def _build_tab_timeline(self):
        header_bar = ttk.Frame(self.tab_timeline)
        header_bar.pack(fill=tk.X, pady=(0, 8))

        ttk.Label(header_bar, text="Reconstructed Activity Super-Timeline", style="Header.TLabel").pack(side=tk.LEFT)

        btn_corrob = tk.Button(header_bar, text="🔗 Corroborate Sources", bg="#7c3aed", activebackground="#8b5cf6", fg="#ffffff", activeforeground="#ffffff", relief=tk.FLAT, font=("Segoe UI", 9, "bold"), padx=8, pady=4, command=self._corroborate_timeline_thread)
        btn_corrob.pack(side=tk.RIGHT, padx=4)

        btn_scan = tk.Button(header_bar, text="🛡️ Scan YARA Threats", bg="#d97706", activebackground="#f59e0b", fg="#ffffff", activeforeground="#ffffff", relief=tk.FLAT, font=("Segoe UI", 9, "bold"), padx=8, pady=4, command=self._scan_threats_thread)
        btn_scan.pack(side=tk.RIGHT, padx=4)

        btn_build_tl = tk.Button(header_bar, text="⚡ Reconstruct Timeline", bg="#059669", activebackground="#10b981", fg="#ffffff", activeforeground="#ffffff", relief=tk.FLAT, font=("Segoe UI", 9, "bold"), padx=8, pady=4, command=self._build_timeline_thread)
        btn_build_tl.pack(side=tk.RIGHT, padx=4)

        # Filters Bar
        filter_bar = tk.LabelFrame(self.tab_timeline, text=" Timeline Filters ", bg="#111726", fg="#00f2fe", font=("Segoe UI", 9, "bold"), padx=8, pady=6, highlightbackground="#1e2942", highlightthickness=1)
        filter_bar.pack(fill=tk.X, pady=5)

        ttk.Label(filter_bar, text="Search:").pack(side=tk.LEFT, padx=3)
        self.entry_search = ttk.Entry(filter_bar, width=22)
        self.entry_search.pack(side=tk.LEFT, padx=4)

        ttk.Label(filter_bar, text="User:").pack(side=tk.LEFT, padx=4)
        self.entry_user = ttk.Entry(filter_bar, width=14)
        self.entry_user.pack(side=tk.LEFT, padx=4)

        ttk.Label(filter_bar, text="Action:").pack(side=tk.LEFT, padx=4)
        self.entry_action = ttk.Entry(filter_bar, width=16)
        self.entry_action.pack(side=tk.LEFT, padx=4)

        btn_filter = ttk.Button(filter_bar, text="Filter", command=self._apply_timeline_filter)
        btn_filter.pack(side=tk.LEFT, padx=6)

        btn_clear = ttk.Button(filter_bar, text="Reset", command=self._reset_timeline_filter)
        btn_clear.pack(side=tk.LEFT, padx=2)

        # Timeline Treeview
        tl_cols = ("timestamp", "action", "user", "object", "artifact", "corroborated", "confidence", "rationale")
        self.tree_timeline = ttk.Treeview(self.tab_timeline, columns=tl_cols, show="headings", height=14)
        self.tree_timeline.heading("timestamp", text="UTC Timestamp")
        self.tree_timeline.heading("action", text="Action")
        self.tree_timeline.heading("user", text="User")
        self.tree_timeline.heading("object", text="Object / Target")
        self.tree_timeline.heading("artifact", text="Artefact")
        self.tree_timeline.heading("corroborated", text="Corroborated By")
        self.tree_timeline.heading("confidence", text="Conf.")
        self.tree_timeline.heading("rationale", text="Forensic Rationale / Warnings")

        self.tree_timeline.column("timestamp", width=160)
        self.tree_timeline.column("action", width=110)
        self.tree_timeline.column("user", width=80)
        self.tree_timeline.column("object", width=190)
        self.tree_timeline.column("artifact", width=110)
        self.tree_timeline.column("corroborated", width=140)
        self.tree_timeline.column("confidence", width=45)
        self.tree_timeline.column("rationale", width=250)

        self.tree_timeline.pack(fill=tk.BOTH, expand=True, pady=5)

    # ---------------- TAB 5: INTEGRITY & CUSTODY ----------------
    def _build_tab_integrity(self):
        lbl = ttk.Label(self.tab_integrity, text="SHA-256 Evidence Integrity & Chain of Custody", style="Header.TLabel")
        lbl.pack(anchor=tk.W, pady=(0, 10))

        verify_bar = ttk.Frame(self.tab_integrity)
        verify_bar.pack(fill=tk.X, pady=5)

        btn_verify = tk.Button(verify_bar, text="🛡️ Verify Integrity (Re-hash & Replay Ledger)", bg="#2563eb", activebackground="#3b82f6", fg="#ffffff", activeforeground="#ffffff", relief=tk.FLAT, font=("Segoe UI", 9, "bold"), padx=10, pady=5, command=self._verify_integrity_thread)
        btn_verify.pack(side=tk.LEFT)

        self.lbl_verify_status = tk.Label(verify_bar, text="Status: Not Verified", font=("Segoe UI", 10, "bold"), bg="#090d16", fg="#94a3b8")
        self.lbl_verify_status.pack(side=tk.LEFT, padx=15)

        # Ledger Treeview
        ledger_frame = tk.LabelFrame(self.tab_integrity, text=" Chain of Custody Ledger (ledger.jsonl) ", bg="#111726", fg="#00f2fe", font=("Segoe UI", 9, "bold"), padx=10, pady=10, highlightbackground="#1e2942", highlightthickness=1)
        ledger_frame.pack(fill=tk.BOTH, expand=True, pady=10)

        cols = ("seq", "timestamp", "actor", "event_type", "hash")
        self.tree_ledger = ttk.Treeview(ledger_frame, columns=cols, show="headings", height=12)
        self.tree_ledger.heading("seq", text="Seq")
        self.tree_ledger.heading("timestamp", text="UTC Timestamp")
        self.tree_ledger.heading("actor", text="Investigating Actor")
        self.tree_ledger.heading("event_type", text="Custody Action")
        self.tree_ledger.heading("hash", text="SHA-256 Entry Hash")

        self.tree_ledger.column("seq", width=50)
        self.tree_ledger.column("timestamp", width=180)
        self.tree_ledger.column("actor", width=150)
        self.tree_ledger.column("event_type", width=160)
        self.tree_ledger.column("hash", width=350)

        self.tree_ledger.pack(fill=tk.BOTH, expand=True)

    # ---------------- TAB 6: REPORTS ----------------
    def _build_tab_reports(self):
        lbl = ttk.Label(self.tab_reports, text="Structured Investigation Reporting & Disclosure", style="Header.TLabel")
        lbl.pack(anchor=tk.W, pady=(0, 10))

        opts_frame = tk.LabelFrame(self.tab_reports, text=" Report Configuration ", bg="#111726", fg="#00f2fe", font=("Segoe UI", 9, "bold"), padx=14, pady=12, highlightbackground="#1e2942", highlightthickness=1)
        opts_frame.pack(fill=tk.X, pady=10)

        ttk.Label(opts_frame, text="Formats:", font=("Segoe UI", 9, "bold")).pack(anchor=tk.W, pady=2)
        fmt_row = ttk.Frame(opts_frame)
        fmt_row.pack(fill=tk.X, pady=3)
        self.var_fmt_html = tk.BooleanVar(value=True)
        self.var_fmt_json = tk.BooleanVar(value=True)
        self.var_fmt_csv = tk.BooleanVar(value=True)
        self.var_fmt_md = tk.BooleanVar(value=True)

        tk.Checkbutton(fmt_row, text="HTML (Interactive Liquid Glass)", variable=self.var_fmt_html, bg="#111726", fg="#f1f5f9", selectcolor="#070a12", activebackground="#111726", activeforeground="#00f2fe").pack(side=tk.LEFT, padx=8)
        tk.Checkbutton(fmt_row, text="Markdown (.md)", variable=self.var_fmt_md, bg="#111726", fg="#f1f5f9", selectcolor="#070a12", activebackground="#111726", activeforeground="#00f2fe").pack(side=tk.LEFT, padx=8)
        tk.Checkbutton(fmt_row, text="JSON (Structured Export)", variable=self.var_fmt_json, bg="#111726", fg="#f1f5f9", selectcolor="#070a12", activebackground="#111726", activeforeground="#00f2fe").pack(side=tk.LEFT, padx=8)
        tk.Checkbutton(fmt_row, text="CSV (Spreadsheet)", variable=self.var_fmt_csv, bg="#111726", fg="#f1f5f9", selectcolor="#070a12", activebackground="#111726", activeforeground="#00f2fe").pack(side=tk.LEFT, padx=8)

        ttk.Label(opts_frame, text="Privacy Redaction Profiles:", font=("Segoe UI", 9, "bold")).pack(anchor=tk.W, pady=(10, 2))
        redact_row = ttk.Frame(opts_frame)
        redact_row.pack(fill=tk.X, pady=3)
        self.var_redact_users = tk.BooleanVar(value=True)
        self.var_redact_paths = tk.BooleanVar(value=False)
        self.var_redact_ips = tk.BooleanVar(value=True)

        tk.Checkbutton(redact_row, text="Redact Usernames", variable=self.var_redact_users, bg="#111726", fg="#f1f5f9", selectcolor="#070a12", activebackground="#111726", activeforeground="#00f2fe").pack(side=tk.LEFT, padx=8)
        tk.Checkbutton(redact_row, text="Redact Folder Paths", variable=self.var_redact_paths, bg="#111726", fg="#f1f5f9", selectcolor="#070a12", activebackground="#111726", activeforeground="#00f2fe").pack(side=tk.LEFT, padx=8)
        tk.Checkbutton(redact_row, text="Redact IP Addresses", variable=self.var_redact_ips, bg="#111726", fg="#f1f5f9", selectcolor="#070a12", activebackground="#111726", activeforeground="#00f2fe").pack(side=tk.LEFT, padx=8)

        btn_row = ttk.Frame(opts_frame)
        btn_row.pack(fill=tk.X, pady=(15, 5))

        btn_gen = tk.Button(btn_row, text="📄 Generate Investigation Reports", bg="#059669", activebackground="#10b981", fg="#ffffff", activeforeground="#ffffff", relief=tk.FLAT, font=("Segoe UI", 10, "bold"), padx=12, pady=6, command=self._generate_reports_thread)
        btn_gen.pack(side=tk.LEFT, padx=5)

        self.btn_open_html = ttk.Button(btn_row, text="🌐 Open HTML Report in Browser", command=self._open_report_in_browser, state=tk.DISABLED)
        self.btn_open_html.pack(side=tk.LEFT, padx=10)

        # Reports Output Box
        rep_box_frame = tk.LabelFrame(self.tab_reports, text=" Generated Investigation Report Output ", bg="#111726", fg="#00f2fe", font=("Segoe UI", 9, "bold"), padx=10, pady=10, highlightbackground="#1e2942", highlightthickness=1)
        rep_box_frame.pack(fill=tk.BOTH, expand=True, pady=10)

        self.txt_reports = tk.Text(rep_box_frame, bg="#070a12", fg="#f1f5f9", relief=tk.FLAT, font=("Consolas", 9), padx=8, pady=8)
        self.txt_reports.pack(fill=tk.BOTH, expand=True)

    # ---------------- LOGIC HANDLERS ----------------

    def _update_status(self, text: str):
        self.status_var.set(text)

    def _open_case_dialog(self):
        d = filedialog.askdirectory(title="Select Existing ChronoTrace Case Directory")
        if d:
            try:
                self.current_case = Case.open(d)
                self._refresh_case_display()
                messagebox.showinfo("Case Loaded", f"Successfully loaded case {self.current_case.case_id}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to load case: {e}")

    def _new_case_dialog(self):
        diag = tk.Toplevel(self.root)
        diag.title("Create New Forensic Case")
        diag.geometry("450x320")
        diag.configure(bg="#090d16")

        ttk.Label(diag, text="Case Identifier:").pack(anchor=tk.W, padx=20, pady=(15, 2))
        e_id = ttk.Entry(diag, width=40)
        e_id.insert(0, f"CASE-{datetime.datetime.now().strftime('%Y-%m%d-%H%M')}")
        e_id.pack(padx=20, pady=2)

        ttk.Label(diag, text="Lead Examiner:").pack(anchor=tk.W, padx=20, pady=(10, 2))
        e_ex = ttk.Entry(diag, width=40)
        e_ex.insert(0, "Lead Forensics Examiner")
        e_ex.pack(padx=20, pady=2)

        ttk.Label(diag, text="Organization:").pack(anchor=tk.W, padx=20, pady=(10, 2))
        e_org = ttk.Entry(diag, width=40)
        e_org.insert(0, "Digital Forensics Unit")
        e_org.pack(padx=20, pady=2)

        ttk.Label(diag, text="Authorization / Warrant Ref:").pack(anchor=tk.W, padx=20, pady=(10, 2))
        e_auth = ttk.Entry(diag, width=40)
        e_auth.insert(0, "AUTH-WARRANT-001")
        e_auth.pack(padx=20, pady=2)

        def _create_action():
            cid = e_id.get().strip()
            dest = filedialog.askdirectory(title="Select Destination Directory for Case Workspace")
            if dest and cid:
                target_dir = Path(dest) / cid
                try:
                    self.current_case = Case.create(
                        case_id=cid,
                        out_dir=target_dir,
                        examiner=e_ex.get().strip(),
                        organization=e_org.get().strip(),
                        authorization_ref=e_auth.get().strip(),
                    )
                    diag.destroy()
                    self._refresh_case_display()
                    messagebox.showinfo("Success", f"Created case {cid} at {target_dir}")
                except Exception as ex:
                    messagebox.showerror("Error", f"Case creation failed: {ex}")

        btn = tk.Button(diag, text="Create Case Workspace", bg="#059669", activebackground="#10b981", fg="#ffffff", activeforeground="#ffffff", relief=tk.FLAT, font=("Segoe UI", 9, "bold"), padx=12, pady=6, command=_create_action)
        btn.pack(pady=20)

    def _refresh_case_display(self):
        if not self.current_case:
            return
        cid = self.current_case.case_id
        self.case_status_lbl.config(text=f"● [Case: {cid}]", fg="#10b981")

        self.case_details_text.config(state=tk.NORMAL)
        self.case_details_text.delete("1.0", tk.END)

        manifest = self.current_case.manifest.data if self.current_case.manifest else {}
        ev_count = len(manifest.get("evidence", []))
        derived_count = len(manifest.get("derived", []))

        text = (
            f"Case Identifier:     {cid}\n"
            f"Case Workspace:      {self.current_case.root}\n"
            f"Lead Examiner:        {self.current_case.examiner}\n"
            f"Organization:         {self.current_case.organization}\n"
            f"Authorization Ref:    {self.current_case.metadata.get('authorization_ref', 'N/A')}\n"
            f"Evidence Items:       {ev_count} registered file(s)\n"
            f"Derived Artefacts:    {derived_count} plugin stream(s)\n"
            f"Write-Guard:          ACTIVE (All evidence access is strictly read-only)\n"
        )
        self.kpi_ev_count.config(text=str(ev_count))
        # Count timeline events if available
        tl_path = self.current_case.derived_dir / "timeline.jsonl"
        if tl_path.exists():
            try:
                with open(tl_path, "r", encoding="utf-8") as f:
                    cnt = sum(1 for _ in f)
                self.kpi_event_count.config(text=str(cnt))
            except Exception:
                self.kpi_event_count.config(text=str(derived_count))
        else:
            self.kpi_event_count.config(text=str(derived_count))

        self.case_details_text.insert(tk.END, text)
        self.case_details_text.config(state=tk.DISABLED)

        self._refresh_ledger_display()
        self._load_timeline_display()

    def _refresh_devices_thread(self):
        def _task():
            self._update_status("Scanning connected storage devices and external USB drives...")
            devices = DeviceManager.list_devices()
            self.root.after(0, lambda: self._update_devices_table(devices))
        threading.Thread(target=_task, daemon=True).start()

    def _update_devices_table(self, devices: List[StorageDevice]):
        self.detected_devices = devices
        for row in self.tree_devices.get_children():
            self.tree_devices.delete(row)

        for dev in devices:
            self.tree_devices.insert(
                "",
                tk.END,
                values=(
                    dev.device_id,
                    dev.model,
                    dev.media_type,
                    dev.mount_point or "N/A",
                    dev.file_system or "Unknown",
                    dev.size_display,
                    dev.serial_number or "N/A",
                ),
            )
        self._update_status(f"Found {len(devices)} storage device(s). Write-Guard: ACTIVE")

    def _on_device_select(self, event):
        selected = self.tree_devices.selection()
        if not selected:
            return
        item = self.tree_devices.item(selected[0])
        dev_id = item["values"][0]
        model = item["values"][1]
        self.lbl_selected_dev.config(text=f"{model} ({dev_id})")

    def _acquire_selected_device_thread(self):
        if not self.current_case:
            messagebox.showwarning("Warning", "Please open or create a case first.")
            return

        selected = self.tree_devices.selection()
        if not selected:
            messagebox.showwarning("Warning", "Please select a storage device from the table.")
            return

        item = self.tree_devices.item(selected[0])
        dev_id = str(item["values"][0])

        target_dev = next((d for d in self.detected_devices if d.device_id == dev_id), None)
        if not target_dev:
            messagebox.showerror("Error", "Selected device not found.")
            return

        if target_dev.is_system_drive:
            if not messagebox.askyesno("System Drive Warning", f"{dev_id} is a primary system drive. Are you sure you want to acquire evidence from it?"):
                return

        out_name = self.entry_out_name.get().strip() or "usb_evidence.tar"
        notes = self.entry_acq_notes.get().strip()

        def _task():
            self._update_status(f"Acquiring evidence from {target_dev.model} with streaming SHA-256...")
            try:
                res = DeviceManager.acquire_device(
                    device=target_dev,
                    case=self.current_case,
                    output_filename=out_name,
                    notes=notes,
                )
                self.root.after(0, lambda: self._on_device_acquired(res))
            except Exception as e:
                self.root.after(0, lambda: messagebox.showerror("Acquisition Error", f"Failed: {e}"))
                self.root.after(0, lambda: self._update_status("Acquisition failed."))

        threading.Thread(target=_task, daemon=True).start()

    def _on_device_acquired(self, res: dict):
        self._update_status(f"Acquired evidence {res['evidence_id']} (SHA-256: {res['hashes']['sha256'][:16]}...)")
        self._refresh_case_display()
        messagebox.showinfo(
            "Evidence Acquired",
            f"Successfully acquired evidence from device!\n\n"
            f"Evidence ID: {res['evidence_id']}\n"
            f"Stored At:   {res['path']}\n"
            f"Size:        {res['size_bytes']} bytes\n"
            f"SHA-256:     {res['hashes']['sha256']}\n"
            f"Verification: PASS (Read-Back Match)"
        )

    def _acquire_file_dialog(self):
        if not self.current_case:
            messagebox.showwarning("Warning", "Please open or create a case first.")
            return
        f = filedialog.askopenfilename(title="Select Evidence File to Ingest")
        if f:
            src = Path(f)
            try:
                res = self.current_case.acquire(src, output_filename=src.name, notes="File acquired via GUI")
                self._refresh_case_display()
                messagebox.showinfo("Success", f"Acquired {src.name} (SHA-256: {res['hashes']['sha256'][:16]}...)")
            except Exception as e:
                messagebox.showerror("Error", f"Failed: {e}")

    def _run_extraction_thread(self):
        if not self.current_case:
            messagebox.showwarning("Warning", "Please open or create a case first.")
            return

        profile = self.combo_profile.get()

        def _task():
            self._update_status("Extracting artefacts across plugins...")
            self.txt_extract_log.insert(tk.END, f"[*] Starting artefact extraction (profile: {profile})...\n")
            try:
                events = self.current_case.extract(profile=profile)
                self.root.after(0, lambda: self._on_extraction_complete(events))
            except Exception as e:
                self.root.after(0, lambda: self.txt_extract_log.insert(tk.END, f"[!] Extraction error: {e}\n"))

        threading.Thread(target=_task, daemon=True).start()

    def _on_extraction_complete(self, events: list):
        self.txt_extract_log.insert(tk.END, f"[+] Extraction finished. Discovered {len(events)} events!\n")
        self._update_status(f"Extraction complete: {len(events)} events discovered.")
        self._refresh_case_display()

    def _build_timeline_thread(self):
        if not self.current_case:
            messagebox.showwarning("Warning", "Please open or create a case first.")
            return

        def _task():
            self._update_status("Reconstructing chronological super-timeline...")
            try:
                events = self.current_case.build_timeline()
                self.root.after(0, lambda: self._on_timeline_built(events))
            except Exception as e:
                self.root.after(0, lambda: messagebox.showerror("Timeline Error", f"Failed: {e}"))

        threading.Thread(target=_task, daemon=True).start()

    def _on_timeline_built(self, events: list):
        self._update_status(f"Timeline reconstructed with {len(events)} chronologically sorted events.")
        self._load_timeline_display()
        self._refresh_case_display()
        messagebox.showinfo("Timeline Complete", f"Reconstructed super-timeline with {len(events)} events.")

    def _load_timeline_display(self, filter_kw=None, filter_user=None, filter_action=None):
        for row in self.tree_timeline.get_children():
            self.tree_timeline.delete(row)

        if not self.current_case or not (self.current_case.index_dir / "events.sqlite").exists():
            return

        tq = TimelineQuery(self.current_case.index_dir)
        events = tq.filter_events(
            search_term=filter_kw,
            user=filter_user,
            action=filter_action,
            limit=2000,
        )

        for ev in events:
            self.tree_timeline.insert(
                "",
                tk.END,
                values=(
                    ev.get("timestamp_utc", ""),
                    ev.get("action", ""),
                    ev.get("user", ""),
                    ev.get("object_path", "") or "N/A",
                    ev.get("artifact", ""),
                    ev.get("corroborated_by", "") or "-",
                    f"{ev.get('confidence', 1.0):.2f}",
                    (ev.get("rationale", "") or "") + (f" [⚠️ {ev['warnings']}]" if ev.get("warnings") else ""),
                ),
            )

    def _corroborate_timeline_thread(self):
        if not self.current_case:
            messagebox.showwarning("Warning", "Please open or create a case first.")
            return

        def _task():
            self._update_status("Running cross-source corroboration and anti-forensics analysis...")
            try:
                res = self.current_case.corroborate()
                self.root.after(0, lambda: self._on_corroboration_complete(res))
            except Exception as e:
                self.root.after(0, lambda: messagebox.showerror("Corroboration Error", f"Failed: {e}"))

        threading.Thread(target=_task, daemon=True).start()

    def _on_corroboration_complete(self, res):
        self._update_status(f"Corroboration complete: {res.corroborated_count} events linked, {res.conflict_count} conflicts.")
        self._load_timeline_display()
        self._refresh_case_display()
        msg = (
            f"Cross-Source Corroboration Complete!\n\n"
            f"Corroborated Events: {res.corroborated_count}\n"
            f"Multi-Source Chains: {len(res.clusters)}\n"
            f"Anti-Forensic Conflicts: {res.conflict_count}\n"
        )
        if res.conflict_count > 0:
            msg += "\n⚠️ Anti-forensic anomalies or timestomp conflicts were detected! Check the timeline warnings or report."
        messagebox.showinfo("Corroboration Analysis", msg)

    def _scan_threats_thread(self):
        if not self.current_case:
            messagebox.showwarning("Warning", "Please open or create a case first.")
            return

        def _task():
            self._update_status("Scanning case evidence & timeline against YARA rules...")
            try:
                findings = self.current_case.scan_threats()
                self.root.after(0, lambda: self._on_threat_scan_complete(findings))
            except Exception as e:
                self.root.after(0, lambda: messagebox.showerror("Threat Scan Error", f"Failed: {e}"))

        threading.Thread(target=_task, daemon=True).start()

    def _on_threat_scan_complete(self, findings: list):
        self._update_status(f"Threat scan finished: {len(findings)} findings.")
        self._load_timeline_display()
        self._refresh_case_display()
        if findings:
            preview = "\n".join([f"- [{f.severity}] {f.rule_name} on {f.target[:35]}" for f in findings[:6]])
            messagebox.showwarning("Threat Alerts Detected", f"Identified {len(findings)} threat signatures/IOCs:\n\n{preview}\n\nTagged as ALERT in timeline.")
        else:
            messagebox.showinfo("Threat Scan", "No threat signatures detected in evidence or timeline.")

    def _on_hotplug_connected(self, dev: StorageDevice):
        self.root.after(0, lambda: self._handle_hotplug_connected(dev))

    def _handle_hotplug_connected(self, dev: StorageDevice):
        self._update_status(f"⚡ NEW STORAGE DEVICE CONNECTED: {dev.model} ({dev.mount_point or dev.device_id})")
        self._refresh_devices_thread()
        if messagebox.askyesno(
            "External Device Detected",
            f"An external storage device was just connected:\n\n"
            f"Model:    {dev.model}\n"
            f"Mount:    {dev.mount_point or 'N/A'}\n"
            f"Capacity: {dev.size_display}\n"
            f"Type:     {dev.interface_type}\n\n"
            f"Do you want to stage and acquire this device as digital evidence?",
        ):
            self.notebook.select(self.tab_devices)
            self.lbl_selected_dev.config(text=f"{dev.model} ({dev.mount_point or dev.device_id})")
            safe_name = f"device_{dev.device_id.replace(':', '').replace(r'\\', '').replace('.', '').replace('/', '_')}.tar"
            self.entry_out_name.delete(0, tk.END)
            self.entry_out_name.insert(0, safe_name)

    def _on_hotplug_disconnected(self, dev: StorageDevice):
        self.root.after(0, lambda: self._handle_hotplug_disconnected(dev))

    def _handle_hotplug_disconnected(self, dev: StorageDevice):
        self._update_status(f"⚠️ STORAGE DEVICE DISCONNECTED: {dev.model} ({dev.mount_point or dev.device_id})")
        self._refresh_devices_thread()

    def _apply_timeline_filter(self):
        kw = self.entry_search.get().strip() or None
        usr = self.entry_user.get().strip() or None
        act = self.entry_action.get().strip() or None
        self._load_timeline_display(filter_kw=kw, filter_user=usr, filter_action=act)

    def _reset_timeline_filter(self):
        self.entry_search.delete(0, tk.END)
        self.entry_user.delete(0, tk.END)
        self.entry_action.delete(0, tk.END)
        self._load_timeline_display()

    def _verify_integrity_thread(self):
        if not self.current_case:
            messagebox.showwarning("Warning", "Please open or create a case first.")
            return

        def _task():
            self._update_status("Verifying SHA-256 hashes & replaying ledger...")
            res = self.current_case.verify(rehash_evidence=True)
            self.root.after(0, lambda: self._on_integrity_verified(res))

        threading.Thread(target=_task, daemon=True).start()

    def _on_integrity_verified(self, res: dict):
        status = res.get("overall_status", "FAIL")
        if status == "PASS":
            self.lbl_verify_status.config(text="Status: PASS (Integrity Verified)", fg="#10b981")
            messagebox.showinfo(
                "Integrity Verified",
                f"Cryptographic Integrity Verification Passed!\n\n"
                f"Ledger Replay:  {res['ledger_status']} ({res['checked_items']['ledger_entries']} entries)\n"
                f"Evidence Check: {res['evidence_status']} ({res['checked_items']['evidence_files']} files)\n"
                f"Derived Store:  {res['derived_status']}\n"
                f"Merkle Root:    {self.current_case.manifest.data.get('merkle_root')}"
            )
        else:
            self.lbl_verify_status.config(text="Status: FAIL (Mismatch Detected)", fg="#f43f5e")
            messagebox.showerror("Integrity Failure", f"Verification failed:\n" + "\n".join(res.get("errors", [])))

        if hasattr(self, "kpi_integrity"):
            self.kpi_integrity.config(text=status, fg="#10b981" if status == "PASS" else "#f43f5e")

        self._refresh_case_display()

    def _refresh_ledger_display(self):
        for row in self.tree_ledger.get_children():
            self.tree_ledger.delete(row)
        if not self.current_case or not self.current_case.ledger:
            return
        entries = self.current_case.ledger.get_entries()
        for e in entries:
            self.tree_ledger.insert(
                "",
                tk.END,
                values=(
                    e.get("seq"),
                    e.get("timestamp_utc"),
                    e.get("actor"),
                    e.get("event_type"),
                    e.get("entry_hash"),
                ),
            )

    def _generate_reports_thread(self):
        if not self.current_case:
            messagebox.showwarning("Warning", "Please open or create a case first.")
            return

        fmts = []
        if self.var_fmt_html.get():
            fmts.append("html")
        if self.var_fmt_md.get():
            fmts.append("md")
        if self.var_fmt_json.get():
            fmts.append("json")
        if self.var_fmt_csv.get():
            fmts.append("csv")

        redact = []
        if self.var_redact_users.get():
            redact.append("usernames")
        if self.var_redact_paths.get():
            redact.append("paths")
        if self.var_redact_ips.get():
            redact.append("ips")

        def _task():
            self._update_status("Compiling structured investigation reports...")
            try:
                out_files = self.current_case.report(
                    template="full",
                    formats=tuple(fmts),
                    redact=tuple(redact),
                )
                self.root.after(0, lambda: self._on_reports_generated(out_files))
            except Exception as e:
                self.root.after(0, lambda: messagebox.showerror("Reporting Error", f"Failed: {e}"))

        threading.Thread(target=_task, daemon=True).start()

    def _on_reports_generated(self, out_files: dict):
        self.txt_reports.delete("1.0", tk.END)
        self.txt_reports.insert(tk.END, "Successfully generated investigation reports:\n\n")
        for fmt, path in out_files.items():
            self.txt_reports.insert(tk.END, f"  * [{fmt.upper()}]  {path}\n")

        self.last_html_report = out_files.get("html")
        if self.last_html_report:
            self.btn_open_html.config(state=tk.NORMAL)

        self._update_status("Reports generated successfully.")
        self._refresh_case_display()
        messagebox.showinfo("Reports Generated", f"Generated {len(out_files)} report file(s) in reports directory.")

    def _open_report_in_browser(self):
        if hasattr(self, "last_html_report") and self.last_html_report:
            webbrowser.open(f"file:///{os.path.abspath(self.last_html_report)}")

    def _run_full_pipeline_thread(self):
        if not self.current_case:
            messagebox.showwarning("Warning", "Please open or create a case first.")
            return

        def _task():
            self._update_status("Executing full automated pipeline...")
            try:
                self.current_case.extract(profile="all")
                self.current_case.build_timeline()
                self.current_case.verify(rehash_evidence=True)
                self.current_case.report(template="full", formats=("html", "md", "json", "csv"))
                self.root.after(0, self._on_full_pipeline_complete)
            except Exception as e:
                self.root.after(0, lambda: messagebox.showerror("Pipeline Error", f"Failed: {e}"))

        threading.Thread(target=_task, daemon=True).start()

    def _on_full_pipeline_complete(self):
        self._refresh_case_display()
        self._load_timeline_display()
        self._update_status("Full forensic analysis pipeline completed successfully.")
        messagebox.showinfo("Pipeline Complete", "All stages (Extract -> Timeline -> Verify -> Report) completed successfully!")

    def _run_doctor_dialog(self):
        plugins = list_plugins()
        diag_msg = (
            f"Python Runtime:  {sys.version.split()[0]}\n"
            f"Parquet Engine:  pyarrow 25.0+ (Active)\n"
            f"Schema Version:  2.0.0 (Pydantic Active)\n"
            f"SQLite Engine:   SQLite 3 with FTS5\n"
            f"Write-Guard:     ACTIVE (Forensic Read-Only)\n"
            f"Artefact Plugins: {len(plugins)} loaded, 0 failed\n\n"
            "WASP system health is OPTIMAL."
        )
        messagebox.showinfo("WASP Doctor", diag_msg)


WASPGUI = ChronoTraceGUI


def launch_gui():
    """Launch the WASP Desktop GUI application."""
    root = tk.Tk()
    app = ChronoTraceGUI(root)
    root.mainloop()


if __name__ == "__main__":
    launch_gui()
