"""Command-line interface: ``quantumai audit`` and ``quantumai readme``."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Callable, Optional

import click
from rich.console import Console
from rich.markup import escape
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TaskProgressColumn, TextColumn
from rich.table import Table

from . import __version__
from .core import (
    DEFAULT_MODEL,
    SEVERITIES,
    SEVERITY_RANK,
    AuditReport,
    CodeAnalyzer,
    QuantumAIError,
)
from .readme import ReadmeGenerator

console = Console()
err_console = Console(stderr=True)

SEVERITY_STYLE = {
    "critical": "bold white on red",
    "high": "bold red",
    "medium": "yellow",
    "low": "cyan",
    "info": "dim",
}
STAGE_LABEL = {"scan": "Parsing Python files", "ai": "Reviewing with OpenAI"}

PATH_ARG = click.Path(exists=True, file_okay=False, path_type=Path)


def _progress() -> "tuple[Progress, Callable[[str, int, int], None]]":
    """A transient progress bar plus the callback CodeAnalyzer reports into."""
    bar = Progress(SpinnerColumn(), TextColumn("[bold]{task.description}"), BarColumn(),
                   TaskProgressColumn(), console=console, transient=True)
    task = bar.add_task("Starting", total=None)

    def callback(stage: str, done: int, total: int) -> None:
        bar.update(task, description=STAGE_LABEL.get(stage, stage), completed=done, total=total or 1)

    return bar, callback


def _fail(message: str, code: int = 2) -> None:
    err_console.print(f"[bold red]Error:[/] {escape(message)}")
    sys.exit(code)


def _render_report(report: AuditReport) -> None:
    counts = report.counts()
    badges = "  ".join(
        f"[{SEVERITY_STYLE[s]}] {s}: {counts[s]} [/]" for s in reversed(SEVERITIES) if counts[s]
    ) or "[green]No findings[/]"
    mode = f"static + {report.model}" if report.ai_used else "static only (--no-ai)"
    console.print(Panel(
        f"[bold]{report.modules_scanned}[/] Python files scanned   Mode: {escape(mode)}\n{badges}",
        title="QuantumAI audit", border_style="blue", expand=False,
    ))

    if report.ai_summaries:
        console.print(Panel(escape(" ".join(report.ai_summaries)), title="AI summary",
                            border_style="dim", expand=False))

    if report.findings:
        table = Table(show_lines=False, header_style="bold")
        for column in ("Severity", "Location", "Finding", "Source"):
            table.add_column(column, overflow="fold")
        for f in report.findings:
            location = f.file + (f":{f.line}" if f.line else "")
            table.add_row(f"[{SEVERITY_STYLE[f.severity]}]{f.severity}[/]", escape(location),
                          escape(f.title), f.source)
        console.print(table)

        # Full explanations for the findings that deserve attention first.
        for f in (x for x in report.findings if SEVERITY_RANK[x.severity] >= SEVERITY_RANK["medium"]):
            body = escape(f.description)
            if f.recommendation:
                body += f"\n\n[bold]Fix:[/] {escape(f.recommendation)}"
            console.print(Panel(body, title=escape(f"{f.title}  ({f.file}:{f.line or '?'})"),
                                border_style="red" if f.severity in ("high", "critical") else "yellow"))

    for message in report.errors:
        err_console.print(f"[yellow]Warning:[/] {escape(message)}")


@click.group(context_settings={"help_option_names": ["-h", "--help"]})
@click.version_option(__version__, prog_name="quantumai")
def main() -> None:
    """QuantumAI: audit Python repositories and generate READMEs with AST analysis + OpenAI."""


@main.command()
@click.argument("path", default=".", type=PATH_ARG)
@click.option("--model", "-m", default=DEFAULT_MODEL, show_default=True, help="OpenAI model to use.")
@click.option("--no-ai", is_flag=True, help="Static analysis only. Nothing is sent to OpenAI.")
@click.option("--exclude", "-x", multiple=True, metavar="DIR", help="Directory name to skip (repeatable).")
@click.option("--output", "-o", type=click.Path(dir_okay=False, path_type=Path),
              help="Also write the full report as JSON to this file.")
@click.option("--fail-on", type=click.Choice(["none", *SEVERITIES]), default="none", show_default=True,
              help="Exit with status 1 if any finding is at or above this severity (for CI).")
def audit(path: Path, model: str, no_ai: bool, exclude: tuple, output: Optional[Path], fail_on: str) -> None:
    """Scan PATH for security and performance problems."""
    try:
        analyzer = CodeAnalyzer(path, model=model, excludes=exclude)
        bar, callback = _progress()
        with bar:
            modules = analyzer.scan(callback)
            report = analyzer.audit(modules, use_ai=not no_ai, progress=callback)
    except QuantumAIError as exc:
        _fail(str(exc))
        return

    _render_report(report)

    if output:
        output.write_text(json.dumps(report.to_dict(), indent=2), encoding="utf-8")
        console.print(f"[dim]JSON report written to {escape(str(output))}[/]")

    if fail_on != "none":
        worst = report.max_severity()
        if worst and SEVERITY_RANK[worst] >= SEVERITY_RANK[fail_on]:
            sys.exit(1)


@main.command()
@click.argument("path", default=".", type=PATH_ARG)
@click.option("--model", "-m", default=DEFAULT_MODEL, show_default=True, help="OpenAI model to use.")
@click.option("--output", "-o", type=click.Path(dir_okay=False, path_type=Path),
              help="Where to write the README (default: PATH/README.md).")
@click.option("--notes", default="", help="Extra guidance for the writer, e.g. 'emphasize the REST API'.")
@click.option("--force", is_flag=True, help="Overwrite the output file if it already exists.")
def readme(path: Path, model: str, output: Optional[Path], notes: str, force: bool) -> None:
    """Generate a professional README.md for the project at PATH."""
    target = output or path / "README.md"
    try:
        analyzer = CodeAnalyzer(path, model=model)
        bar, callback = _progress()
        with bar:
            summary = analyzer.summarize(analyzer.scan(callback))
            bar.update(bar.task_ids[0], description="Writing README with OpenAI", total=None)
            written = ReadmeGenerator(analyzer.client, model).write(summary, target, notes=notes, force=force)
    except FileExistsError as exc:
        _fail(str(exc))
        return
    except QuantumAIError as exc:
        _fail(str(exc))
        return
    console.print(f"[bold green]README written to {escape(str(written))}[/]")


if __name__ == "__main__":
    main()
