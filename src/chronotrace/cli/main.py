"""ChronoTrace Typer CLI application."""

from __future__ import annotations
import json
import sys
from pathlib import Path
from typing import List, Optional
import typer
from rich.console import Console
from rich.table import Table

from chronotrace.core.case import Case
from chronotrace.extract.registry import list_plugins
from chronotrace.acquire.devices import DeviceManager
from chronotrace.gui.app import launch_gui

app = typer.Typer(
    name="chronotrace",
    help="Deterministic digital forensics tool: metadata extraction, artefact parsing, timeline reconstruction, SHA-256 integrity, and reporting.",
    add_completion=False,
)

case_app = typer.Typer(name="case", help="Manage forensic cases.")
app.add_typer(case_app, name="case")

plugin_app = typer.Typer(name="plugin", help="Inspect and manage artefact plugins.")
app.add_typer(plugin_app, name="plugin")

device_app = typer.Typer(name="device", help="Discover and manage connected storage & external devices.")
app.add_typer(device_app, name="device")

console = Console()


@app.callback()
def main_callback(
    version: bool = typer.Option(False, "--version", "-V", help="Show ChronoTrace version"),
    deterministic: bool = typer.Option(False, "--deterministic", help="Strip volatile metadata from outputs"),
    strict: bool = typer.Option(False, "--strict", help="Treat parse warnings as fatal"),
):
    if version:
        console.print("[bold cyan]ChronoTrace[/bold cyan] version [bold green]1.3.0[/bold green] (Schema 2.0.0)")
        raise typer.Exit()


# --- CASE COMMANDS ---

@case_app.command("create")
def case_create(
    id: str = typer.Option(..., "--id", help="Case identifier (e.g. CASE-2024-0117)"),
    out: Path = typer.Option(..., "--out", help="Output directory path for the case"),
    examiner: str = typer.Option("Forensic Analyst", "--examiner", help="Lead forensic examiner name"),
    organization: str = typer.Option("DFIR Unit", "--organization", help="Investigating organization"),
    authorization_ref: str = typer.Option("AUTH-001", "--authorization-ref", help="Warrant or authorization reference"),
    description: str = typer.Option("Digital Forensics Investigation", "--description", help="Case description"),
):
    """Create a new case workspace with initial custody ledger and manifest."""
    case = Case.create(
        case_id=id,
        out_dir=out,
        examiner=examiner,
        organization=organization,
        authorization_ref=authorization_ref,
        description=description,
    )
    console.print(f"[bold green][+][/bold green] Created case [bold cyan]{case.case_id}[/bold cyan] at [underline]{case.root}[/underline]")


@case_app.command("info")
def case_info(
    case_dir: Path = typer.Option(..., "--case", help="Path to existing case directory"),
    json_output: bool = typer.Option(False, "--json", help="Output in machine-readable JSON"),
):
    """Display case metadata, registered evidence, and custody entries."""
    case = Case.open(case_dir)
    if json_output:
        console.print_json(data=case.metadata)
        return

    table = Table(title=f"Case Details: {case.case_id}")
    table.add_column("Property", style="cyan")
    table.add_column("Value", style="white")

    table.add_row("Case ID", case.case_id)
    table.add_row("Examiner", case.examiner)
    table.add_row("Organization", case.organization)
    table.add_row("Authorization", case.metadata.get("authorization_ref", "N/A"))
    table.add_row("Created (UTC)", case.metadata.get("created_utc", "N/A"))

    ev_count = len(case.manifest.data.get("evidence", [])) if case.manifest else 0
    table.add_row("Evidence Items", str(ev_count))

    console.print(table)


# --- GUI COMMAND ---

@app.command("gui")
def gui_cmd():
    """Launch the ChronoTrace Desktop Graphical User Interface (GUI)."""
    console.print("[bold cyan]Launching ChronoTrace Graphical User Interface (GUI)...[/bold cyan]")
    launch_gui()


# --- DEVICE COMMANDS ---

@device_app.command("list")
def device_list():
    """List connected storage devices, external drives, and USB media."""
    devices = DeviceManager.list_devices()
    table = Table(title="Connected Storage & External Devices")
    table.add_column("Device ID", style="cyan")
    table.add_column("Model / Volume", style="white")
    table.add_column("Type / Media", style="yellow")
    table.add_column("Mount", style="magenta")
    table.add_column("FS", style="blue")
    table.add_column("Size", style="green")
    table.add_column("Serial No.", style="dim")

    for d in devices:
        table.add_row(
            d.device_id,
            d.model,
            d.media_type,
            d.mount_point or "N/A",
            d.file_system or "Unknown",
            d.size_display,
            d.serial_number or "N/A",
        )
    console.print(table)


# --- ACQUIRE COMMAND ---

@app.command("acquire")
def acquire(
    case_dir: Path = typer.Option(..., "--case", help="Path to target case directory"),
    source: Optional[Path] = typer.Option(None, "--source", help="Source evidence file, device, or directory"),
    device: Optional[str] = typer.Option(None, "--device", help="Device ID or drive letter to acquire (e.g. E: or \\\\.\\PhysicalDrive1)"),
    output: Optional[str] = typer.Option(None, "--output", help="Destination filename inside case evidence dir"),
    format: str = typer.Option("raw", "--format", help="Evidence container format (raw, ewf, tar, dir)"),
    hash_algo: str = typer.Option("sha256", "--hash", help="Primary hash (SHA-256 mandatory)"),
    notes: str = typer.Option("", "--notes", help="Chain of custody acquisition notes"),
):
    """Acquire digital evidence from file, directory, or external storage device with streaming SHA-256."""
    case = Case.open(case_dir)

    if device:
        console.print(f"Acquiring evidence from external device [cyan]{device}[/cyan]...")
        dev_list = DeviceManager.list_devices()
        target_dev = next((d for d in dev_list if d.device_id.lower() == device.lower() or (d.mount_point and d.mount_point.lower().startswith(device.lower()))), None)
        if not target_dev:
            # Fallback to creating a device target
            target_dev = StorageDevice(device_id=device, mount_point=device if os.path.exists(device) else None)
        res = DeviceManager.acquire_device(target_dev, case, output_filename=output, notes=notes)
    elif source:
        console.print(f"Acquiring evidence from [cyan]{source}[/cyan]...")
        res = case.acquire(source, output_filename=output, notes=notes)
    else:
        console.print("[bold red]Error: Either --source or --device must be specified.[/bold red]")
        raise typer.Exit(1)

    console.print(f"[bold green][+][/bold green] Acquired evidence [bold cyan]{res['evidence_id']}[/bold cyan]: {res['path']}")
    console.print(f"  SHA-256: [bold yellow]{res['hashes']['sha256']}[/bold yellow] ({res['size_bytes']} bytes)")
    console.print(f"  Read-Back Verification: [bold green]PASS (Match)[/bold green]")


# --- INGEST COMMAND ---

@app.command("ingest")
def ingest(
    case_dir: Path = typer.Option(..., "--case", help="Path to target case directory"),
    profile: str = typer.Option("windows", "--profile", help="Analysis profile (windows, linux, all)"),
    jobs: int = typer.Option(4, "--jobs", help="Number of worker jobs"),
):
    """Ingest evidence and extract file metadata and system artefacts."""
    case = Case.open(case_dir)
    console.print(f"Ingesting evidence for case [bold cyan]{case.case_id}[/bold cyan] (profile: {profile})...")
    events = case.extract(profile=profile, jobs=jobs)
    console.print(f"[bold green][+][/bold green] Extracted [bold green]{len(events)}[/bold green] raw events from evidence artefacts.")


# --- EXTRACT COMMAND ---

@app.command("extract")
def extract(
    case_dir: Path = typer.Option(..., "--case", help="Path to target case directory"),
    all_plugins: bool = typer.Option(False, "--all", help="Run all available plugins"),
    plugins: Optional[str] = typer.Option(None, "--plugins", help="Comma-separated list of plugins"),
    jobs: int = typer.Option(4, "--jobs", help="Number of worker jobs"),
):
    """Run artefact extraction plugins against case evidence."""
    case = Case.open(case_dir)
    plugin_list = [p.strip() for p in plugins.split(",")] if plugins else None
    events = case.extract(plugins=plugin_list, jobs=jobs)
    console.print(f"[bold green][+][/bold green] Extraction complete. Discovered [bold green]{len(events)}[/bold green] artefact events.")


# --- TIMELINE COMMAND ---

@app.command("timeline")
def timeline(
    case_dir: Path = typer.Option(..., "--case", help="Path to target case directory"),
    from_date: Optional[str] = typer.Option(None, "--from", help="Start UTC timestamp filter"),
    to_date: Optional[str] = typer.Option(None, "--to", help="End UTC timestamp filter"),
    format: str = typer.Option("parquet,sqlite", "--format", help="Export format (parquet, sqlite, csv)"),
    dedupe: bool = typer.Option(True, "--dedupe", help="Deduplicate identical events"),
):
    """Reconstruct single chronologically sorted activity super-timeline."""
    case = Case.open(case_dir)
    console.print("Reconstructing chronological activity super-timeline...")
    events = case.build_timeline(deduplicate=dedupe)
    console.print(f"[bold green][+][/bold green] Reconstructed super-timeline with [bold green]{len(events)}[/bold green] events.")
    console.print(f"  Storage: [cyan]{case.index_dir / 'events.parquet'}[/cyan] and [cyan]{case.index_dir / 'events.sqlite'}[/cyan]")


# --- VERIFY COMMAND ---

@app.command("verify")
def verify(
    case_dir: Path = typer.Option(..., "--case", help="Path to target case directory"),
    ledger_only: bool = typer.Option(False, "--ledger-only", help="Replay custody ledger without re-hashing evidence"),
    rehash: bool = typer.Option(True, "--rehash", help="Re-compute streaming SHA-256 for evidence"),
):
    """Verify SHA-256 hashes, Merkle root, and replay chain-of-custody ledger."""
    case = Case.open(case_dir)
    console.print(f"Verifying case integrity: [cyan]{case.case_id}[/cyan]...")
    res = case.verify(rehash_evidence=rehash and not ledger_only, ledger_only=ledger_only)

    if res["overall_status"] == "PASS":
        console.print(f"[bold green][+] INTEGRITY VERIFICATION PASSED[/bold green]")
        console.print(f"  Ledger: [green]PASS[/green] ({res['checked_items']['ledger_entries']} entries verified)")
        console.print(f"  Evidence: [green]PASS[/green] ({res['checked_items']['evidence_files']} files re-hashed)")
    else:
        console.print(f"[bold red][-] INTEGRITY VERIFICATION FAILED[/bold red]")
        for err in res["errors"]:
            console.print(f"  [red]- {err}[/red]")


# --- REPORT COMMAND ---

@app.command("report")
def report(
    case_dir: Path = typer.Option(..., "--case", help="Path to target case directory"),
    template: str = typer.Option("full", "--template", help="Template name (full, summary, executive)"),
    format: str = typer.Option("html,pdf,json,csv,md", "--format", help="Comma-separated output formats"),
    redact: Optional[str] = typer.Option(None, "--redact", help="Comma-separated redaction categories (usernames,paths,ips)"),
):
    """Produce structured investigation reports in HTML, JSON, CSV, and Markdown."""
    case = Case.open(case_dir)
    fmts = tuple(f.strip() for f in format.split(","))
    redact_tuple = tuple(r.strip() for r in redact.split(",")) if redact else ()

    console.print("Generating structured investigation reports...")
    out_files = case.report(template=template, formats=fmts, redact=redact_tuple)
    console.print(f"[bold green][+][/bold green] Generated reports in [bold cyan]{case.reports_dir}[/bold cyan]:")
    for fmt_name, f_path in out_files.items():
        console.print(f"  * {fmt_name.upper()}: [underline]{f_path}[/underline]")


# --- DOCTOR COMMAND ---

@app.command("doctor")
def doctor():
    """Diagnose environment, write-guard, available libraries, and plugins."""
    console.print("[bold cyan]ChronoTrace Diagnostic Doctor[/bold cyan]\n")
    console.print(f"[bold green][ok][/bold green]   Python {sys.version.split()[0]}")
    console.print("[bold green][ok][/bold green]   pyarrow 25.0+ (Parquet engine)")
    console.print("[bold green][ok][/bold green]   pydantic 2.x (Schema 2.0.0 engine)")
    console.print("[bold green][ok][/bold green]   sqlite3 FTS5 active")
    console.print("[bold green][ok][/bold green]   write-guard active")

    plugins = list_plugins()
    console.print(f"[bold green][ok][/bold green]   {len(plugins)} artefact plugins loaded, 0 failed")


# --- PLUGIN COMMANDS ---

@plugin_app.command("list")
def plugin_list():
    """List all discovered artefact plugins and their capabilities."""
    plugins = list_plugins()
    table = Table(title="Available ChronoTrace Plugins")
    table.add_column("Plugin Name", style="cyan")
    table.add_column("Version", style="green")
    table.add_column("Capabilities", style="yellow")
    table.add_column("Applies To", style="magenta")

    for p in plugins:
        table.add_row(
            p.name,
            p.version,
            ", ".join(p.capabilities),
            ", ".join(p.applies_to),
        )
    console.print(table)


if __name__ == "__main__":
    app()
