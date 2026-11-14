"""Файловый ввод-вывод: выбор файла, разбор списков, сохранение результатов, открытие папки."""

from __future__ import annotations

import os
import re
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import Final, Sequence

from rich.console import Console
from rich.prompt import Prompt

from core.checker import ProxyResult

BASE_DIR: Final[Path] = Path(__file__).resolve().parent.parent
RESULTS_DIR: Final[Path] = BASE_DIR / "results"

# [scheme://][user:pass@]ip:port
_LINE_RE: Final[re.Pattern[str]] = re.compile(
    r"^(?:[A-Za-z][A-Za-z0-9+.\-]*://)?"
    r"(?:(?P<auth>[^\s@/:]+:[^\s@/]+)@)?"
    r"(?P<host>(?:\d{1,3}\.){3}\d{1,3}):(?P<port>\d{1,5})$"
)
_SPLIT_RE: Final[re.Pattern[str]] = re.compile(r"[\s|]+")


# ---------------------------------------------------------------------- выбор файла


def _dialog_pick() -> tuple[bool, Path | None]:
    """Диалог tkinter. Возвращает (диалог_доступен, путь_или_None_если_отмена)."""
    try:
        import tkinter as tk
        from tkinter import filedialog
    except ImportError:
        return False, None

    root: tk.Tk | None = None
    try:
        root = tk.Tk()
        root.withdraw()
        root.attributes("-topmost", True)
        root.update()
        root.lift()
        root.focus_force()
        selected = filedialog.askopenfilename(
            parent=root,
            title="Выберите файл с прокси (.txt)",
            filetypes=[("Текстовые файлы", "*.txt"), ("Все файлы", "*.*")],
        )
    except tk.TclError:
        return False, None
    finally:
        if root is not None:
            try:
                root.destroy()
            except tk.TclError:
                pass

    if isinstance(selected, str) and selected:
        return True, Path(selected)
    return True, None


def _normalize_user_path(raw: str) -> Path:
    """Чистит путь, вставленный или перетащенный в консоль (кавычки, экранированные пробелы, ``~``)."""
    text = raw.strip()
    if len(text) >= 2 and text[0] == text[-1] and text[0] in "\"'":
        text = text[1:-1]
    if os.name != "nt":
        text = text.replace("\\ ", " ")
    return Path(os.path.expandvars(os.path.expanduser(text)))


def pick_file(console: Console) -> Path | None:
    """Выбирает файл через диалог; если GUI недоступен — просит ввести или перетащить путь в консоль."""
    available, path = _dialog_pick()
    if available:
        return path if path is not None and path.is_file() else None

    console.print("[yellow]Графический диалог недоступен — введите путь к файлу вручную.[/]")
    console.print("[dim]Можно перетащить файл в окно консоли. Пустая строка — отмена.[/]")
    while True:
        raw = Prompt.ask("Путь к файлу", default="", show_default=False, console=console)
        if not raw.strip():
            return None
        candidate = _normalize_user_path(raw)
        if candidate.is_file():
            return candidate
        console.print(f"[red]Файл не найден:[/] {candidate}")


# ---------------------------------------------------------------------- чтение


def parse_proxy_file(path: Path) -> tuple[list[str], int]:
    """Читает файл с прокси. Форматы: ``ip:port`` и ``user:pass@ip:port`` (префикс ``scheme://`` игнорируется).

    Возвращает (уникальные_прокси, число_пропущенных_некорректных_строк).
    """
    entries: list[str] = []
    skipped = 0
    with path.open("r", encoding="utf-8-sig", errors="ignore") as handle:
        for line in handle:
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            token = _SPLIT_RE.split(stripped, maxsplit=1)[0]
            match = _LINE_RE.match(token)
            if match is None:
                skipped += 1
                continue
            host = match.group("host")
            octets = host.split(".")
            port = int(match.group("port"))
            if any(int(octet) > 255 for octet in octets) or not 1 <= port <= 65535:
                skipped += 1
                continue
            normalized_host = ".".join(str(int(octet)) for octet in octets)
            auth = match.group("auth")
            entries.append(f"{auth}@{normalized_host}:{port}" if auth else f"{normalized_host}:{port}")
    return list(dict.fromkeys(entries)), skipped


# ---------------------------------------------------------------------- сохранение


def make_result_dir(mode_slug: str) -> Path:
    """Создаёт ``results/YYYY-MM-DD_HH-MM-SS_<режим>/``."""
    stamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    path = RESULTS_DIR / f"{stamp}_{mode_slug}"
    path.mkdir(parents=True, exist_ok=True)
    return path


def _write_lines(path: Path, lines: Sequence[str]) -> None:
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        handle.write("\n".join(lines))
        handle.write("\n")


def save_checked(directory: Path, ptype: str, results: Sequence[ProxyResult]) -> list[Path]:
    """Сохраняет ``valid_<type>.txt`` (чистый список) и ``detailed_<type>.txt`` (с пингом и страной)."""
    if not results:
        return []
    valid_path = directory / f"valid_{ptype}.txt"
    detailed_path = directory / f"detailed_{ptype}.txt"
    _write_lines(valid_path, [item.proxy for item in results])
    _write_lines(detailed_path, [item.detailed for item in results])
    return [valid_path, detailed_path]


def save_scraped(directory: Path, ptype: str, proxies: Sequence[str]) -> list[Path]:
    """Сохраняет свежеспарсенные прокси без проверки: ``scraped_<type>.txt``."""
    if not proxies:
        return []
    path = directory / f"scraped_{ptype}.txt"
    _write_lines(path, proxies)
    return [path]


# ---------------------------------------------------------------------- открытие папки


def open_folder(path: Path) -> bool:
    """Открывает папку в файловом менеджере ОС. Возвращает ``False``, если не удалось."""
    try:
        if sys.platform.startswith("win"):
            os.startfile(path)  # type: ignore[attr-defined]  # noqa: S606
        elif sys.platform == "darwin":
            subprocess.Popen(["open", str(path)])  # noqa: S603, S607
        else:
            subprocess.Popen(  # noqa: S603, S607
                ["xdg-open", str(path)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )
    except (OSError, ValueError):
        return False
    return True
