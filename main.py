"""ProxyPulse CLI — быстрый кроссплатформенный парсер и чекер публичных прокси."""

from __future__ import annotations

import asyncio
import signal
import sys
from collections import Counter
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

if sys.version_info < (3, 11):
    sys.exit("ProxyPulse CLI требует Python 3.11 или новее.")

from rich import box
from rich.console import Console
from rich.markup import escape
from rich.panel import Panel
from rich.prompt import Confirm, FloatPrompt, IntPrompt, Prompt
from rich.table import Table

from core.checker import (
    DEFAULT_CONCURRENCY,
    DEFAULT_TIMEOUT,
    MAX_CONCURRENCY,
    MAX_TIMEOUT,
    MIN_CONCURRENCY,
    MIN_TIMEOUT,
    CheckReport,
    ProxyChecker,
    ProxyResult,
)
from core.scraper import PROXY_TYPES, ScrapeReport, scrape
from utils.io_helper import (
    RESULTS_DIR,
    make_result_dir,
    open_folder,
    parse_proxy_file,
    pick_file,
    save_checked,
    save_scraped,
)

if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")  # type: ignore[union-attr]
        sys.stderr.reconfigure(encoding="utf-8")  # type: ignore[union-attr]
    except (OSError, ValueError):
        pass

console = Console()


# ---------------------------------------------------------------------- системные мелочи


def raise_fd_limit(target: int = 4096) -> None:
    """На Linux/macOS поднимает лимит открытых файлов, чтобы 500 потоков не упирались в ulimit."""
    try:
        import resource
    except ImportError:  # Windows
        return
    try:
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        if soft >= target:
            return
        new_soft = target if hard == resource.RLIM_INFINITY else min(target, hard)
        resource.setrlimit(resource.RLIMIT_NOFILE, (new_soft, hard))
    except (ValueError, OSError):
        pass


def pause() -> None:
    Prompt.ask("\n[dim]Нажмите Enter, чтобы вернуться в меню[/]", default="", show_default=False, console=console)


# ---------------------------------------------------------------------- меню и ввод


def render_menu() -> None:
    console.clear()
    console.print(
        Panel.fit(
            "[bold cyan]ProxyPulse CLI[/]\n[dim]Быстрый парсер и чекер публичных прокси[/]",
            border_style="cyan",
            padding=(1, 6),
        )
    )
    table = Table(show_lines=True, box=box.ROUNDED, border_style="cyan", header_style="bold magenta")
    table.add_column("№", justify="center", style="bold yellow", no_wrap=True)
    table.add_column("Действие", style="white")
    table.add_row("1", "Спарсить и сразу проверить прокси (в 1 клик)")
    table.add_row("2", "Проверить свой файл с прокси (.txt)")
    table.add_row("3", "Только спарсить свежие прокси (без проверки)")
    table.add_row("0", "Выход")
    console.print(table)


def ask_types(allow_all: bool) -> list[str]:
    """Выбор типа прокси."""
    console.print("\n[bold]Тип прокси:[/]")
    console.print("  [bold yellow]1[/] HTTP")
    console.print("  [bold yellow]2[/] SOCKS4")
    console.print("  [bold yellow]3[/] SOCKS5")
    choices = ["1", "2", "3"]
    if allow_all:
        console.print("  [bold yellow]4[/] Все сразу")
        choices.append("4")
    answer = Prompt.ask("Ваш выбор", choices=choices, default="1", console=console)
    if answer == "4":
        return list(PROXY_TYPES)
    return [PROXY_TYPES[int(answer) - 1]]


def ask_settings() -> tuple[float, int]:
    """Таймаут и количество потоков с ограничением допустимых диапазонов."""
    timeout = FloatPrompt.ask(
        f"Таймаут, сек ({MIN_TIMEOUT:g}–{MAX_TIMEOUT:g})", default=DEFAULT_TIMEOUT, console=console
    )
    if not MIN_TIMEOUT <= timeout <= MAX_TIMEOUT:
        timeout = min(max(timeout, MIN_TIMEOUT), MAX_TIMEOUT)
        console.print(f"[yellow]Таймаут скорректирован до {timeout:g} сек.[/]")

    threads = IntPrompt.ask(
        f"Потоки ({MIN_CONCURRENCY}–{MAX_CONCURRENCY})", default=DEFAULT_CONCURRENCY, console=console
    )
    if not MIN_CONCURRENCY <= threads <= MAX_CONCURRENCY:
        threads = min(max(threads, MIN_CONCURRENCY), MAX_CONCURRENCY)
        console.print(f"[yellow]Число потоков скорректировано до {threads}.[/]")
    return timeout, threads


# ---------------------------------------------------------------------- вывод статистики


def print_scrape_report(report: ScrapeReport) -> None:
    table = Table(title="Источники", show_lines=True, box=box.ROUNDED, border_style="cyan")
    table.add_column("Источник")
    table.add_column("Тип", justify="center")
    table.add_column("Найдено", justify="right")
    table.add_column("Статус", justify="center")
    for stat in report.stats:
        status = "[green]OK[/]" if stat.ok else "[red]недоступен[/]"
        table.add_row(escape(stat.source), stat.ptype.upper(), f"{stat.found}", status)
    console.print(table)

    summary = Table(title="Итого уникальных", box=box.ROUNDED, border_style="green")
    summary.add_column("Тип", justify="center")
    summary.add_column("Уникальных", justify="right", style="bold green")
    for ptype, items in report.proxies.items():
        summary.add_row(ptype.upper(), f"{len(items)}")
    console.print(summary)
    removed = report.raw_total - report.unique_total
    console.print(f"[dim]Найдено всего: {report.raw_total}, дублей удалено: {removed}[/]")


def _format_countries(report: CheckReport) -> str:
    counter = Counter(item.country for item in report.results)
    return "  ".join(f"{code}({count})" for code, count in counter.most_common(5)) or "—"


def print_check_stats(reports: list[CheckReport], interrupted: bool) -> None:
    title = "Статистика проверки (прервано пользователем)" if interrupted else "Статистика проверки"
    table = Table(title=title, show_lines=True, box=box.ROUNDED, border_style="cyan")
    table.add_column("Тип", justify="center", style="bold")
    table.add_column("Проверено", justify="right")
    table.add_column("Валидных", justify="right", style="bold green")
    table.add_column("Успех", justify="right")
    table.add_column("Лучший пинг", justify="right")
    table.add_column("Средний пинг", justify="right")
    table.add_column("Скорость", justify="right")
    table.add_column("Время", justify="right")
    table.add_column("Топ стран")

    for report in reports:
        success = f"{report.valid / report.checked * 100:.1f}%" if report.checked else "—"
        best = f"{report.results[0].ms} ms" if report.results else "—"
        average = f"{sum(r.ms for r in report.results) // report.valid} ms" if report.results else "—"
        table.add_row(
            report.ptype.upper(),
            f"{report.checked}/{report.total}",
            f"{report.valid}",
            success,
            best,
            average,
            f"{report.speed:.0f} пр/сек",
            f"{report.elapsed:.1f} с",
            _format_countries(report),
        )
    console.print(table)


def offer_open_folder(directory: Path) -> None:
    if Confirm.ask("Открыть папку с результатами?", default=True, console=console):
        if not open_folder(directory):
            console.print(f"[yellow]Не удалось открыть папку автоматически:[/] {directory}")


# ---------------------------------------------------------------------- режимы


@contextmanager
def _sigint_shield() -> Iterator[None]:
    """Во время записи файлов игнорирует Ctrl+C, чтобы повторное нажатие не оборвало сохранение."""
    try:
        previous = signal.signal(signal.SIGINT, signal.SIG_IGN)
    except ValueError:  # не главный поток — защита недоступна
        yield
        return
    try:
        yield
    finally:
        signal.signal(signal.SIGINT, previous if previous is not None else signal.SIG_DFL)


def _report_from_results(
    checker: ProxyChecker, ptype: str, total: int, results_list: list[ProxyResult]
) -> CheckReport:
    """Отчёт строится прямо из списка, переданного чекеру по ссылке, — он переживает любое прерывание."""
    snapshot = checker.snapshot()
    return CheckReport(
        ptype=ptype,
        total=total,
        checked=snapshot.checked,
        elapsed=snapshot.elapsed,
        results=sorted(results_list, key=lambda item: item.ms),
    )


def run_checks(
    entries_by_type: dict[str, list[str]], timeout: float, threads: int, mode_slug: str
) -> None:
    """Последовательно проверяет прокси по типам, сохраняет валид и показывает статистику."""
    reports: list[CheckReport] = []
    interrupted = False

    for ptype, entries in entries_by_type.items():
        # Список передаётся чекеру по ссылке: найденное остаётся здесь даже при Ctrl+C / отмене задач.
        results_list: list[ProxyResult] = []
        checker = ProxyChecker(timeout=timeout, concurrency=threads, console=console)
        console.print(
            f"\n[bold]Проверяю {ptype.upper()}: {len(entries)} адресов[/] "
            "[dim](Ctrl+C — остановить и сохранить найденное)[/]"
        )
        try:
            report = asyncio.run(checker.check(entries, ptype, results_list))
        except (KeyboardInterrupt, asyncio.CancelledError):
            interrupted = True
            report = _report_from_results(checker, ptype, len(entries), results_list)
        reports.append(report)
        if interrupted:
            console.print("\n[yellow]Проверка остановлена — сохраняю то, что уже найдено.[/]")
            break

    console.print()
    print_check_stats(reports, interrupted)

    with_valid = [report for report in reports if report.results]
    if not with_valid:
        console.print("\n[yellow]Валидных прокси не найдено — файлы не создавались.[/]")
        return

    saved: list[Path] = []
    with _sigint_shield():
        out_dir = make_result_dir(mode_slug)
        try:
            for report in with_valid:
                saved.extend(save_checked(out_dir, report.ptype, report.results))
        except OSError as error:
            console.print(f"\n[red]Не удалось записать результаты:[/] {escape(str(error))}")
            return

    files = "\n".join(f"  • {path.name}" for path in saved)
    console.print(
        Panel(
            f"[bold green]Результаты сохранены[/]\n{escape(str(out_dir))}\n\n{files}",
            border_style="green",
        )
    )
    offer_open_folder(out_dir)


def scrape_with_status(types: list[str]) -> ScrapeReport:
    with console.status("[bold cyan]Скачиваю свежие списки с GitHub...[/]", spinner="dots"):
        report = asyncio.run(scrape(types))
    print_scrape_report(report)
    return report


def mode_scrape_and_check() -> None:
    types = ask_types(allow_all=True)
    timeout, threads = ask_settings()

    report = scrape_with_status(types)
    entries_by_type = {ptype: report.proxies[ptype] for ptype in types if report.proxies.get(ptype)}
    if not entries_by_type:
        console.print("\n[red]Не удалось получить ни одного прокси. Проверьте интернет-соединение.[/]")
        return
    run_checks(entries_by_type, timeout, threads, "scrape_check")


def mode_check_file() -> None:
    console.print("\n[bold]Выберите .txt файл с прокси[/] [dim](ip:port или user:pass@ip:port)[/]")
    path = pick_file(console)
    if path is None:
        console.print("[yellow]Файл не выбран.[/]")
        return

    try:
        entries, skipped = parse_proxy_file(path)
    except OSError as error:
        console.print(f"[red]Не удалось прочитать файл:[/] {escape(str(error))}")
        return

    console.print(f"Файл: [cyan]{escape(str(path))}[/]")
    console.print(f"Уникальных прокси: [bold green]{len(entries)}[/], пропущено некорректных строк: {skipped}")
    if not entries:
        console.print("[red]В файле нет корректных прокси.[/]")
        return

    types = ask_types(allow_all=False)
    timeout, threads = ask_settings()
    run_checks({types[0]: entries}, timeout, threads, "check_file")


def mode_scrape_only() -> None:
    report = scrape_with_status(list(PROXY_TYPES))
    if report.unique_total == 0:
        console.print("\n[red]Не удалось получить ни одного прокси. Проверьте интернет-соединение.[/]")
        return

    out_dir = make_result_dir("scrape_only")
    saved: list[Path] = []
    for ptype, items in report.proxies.items():
        saved.extend(save_scraped(out_dir, ptype, items))

    files = "\n".join(f"  • {path.name}" for path in saved)
    console.print(
        Panel(
            f"[bold green]Свежие прокси сохранены (без проверки)[/]\n{escape(str(out_dir))}\n\n{files}",
            border_style="green",
        )
    )
    offer_open_folder(out_dir)


# ---------------------------------------------------------------------- точка входа


def main() -> None:
    raise_fd_limit()
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)

    handlers = {"1": mode_scrape_and_check, "2": mode_check_file, "3": mode_scrape_only}
    while True:
        render_menu()
        try:
            choice = Prompt.ask("Выберите пункт", choices=["0", "1", "2", "3"], console=console)
        except (KeyboardInterrupt, EOFError):
            break
        if choice == "0":
            break
        try:
            handlers[choice]()
        except KeyboardInterrupt:
            console.print("\n[yellow]Операция прервана.[/]")
        except Exception as error:  # noqa: BLE001
            console.print(f"\n[red]Непредвиденная ошибка:[/] {escape(repr(error))}")
        try:
            pause()
        except (KeyboardInterrupt, EOFError):
            break
    console.print("\n[cyan]До встречи![/]")


if __name__ == "__main__":
    main()
