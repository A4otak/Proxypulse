"""Высокоскоростной асинхронный чекер прокси (aiohttp + aiohttp-socks) с живым прогрессом rich."""

from __future__ import annotations

import asyncio
import ipaddress
import json
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Final

import aiohttp
from aiohttp_socks import ProxyConnector, ProxyError
from rich.console import Console
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    ProgressColumn,
    Task,
    TextColumn,
    TimeElapsedColumn,
    TimeRemainingColumn,
)
from rich.text import Text

PROXY_TYPES: Final[tuple[str, ...]] = ("http", "socks4", "socks5")

# Основная проверка: быстрый GeoIP без жёстких лимитов, ответ {"ip": "...", "country": "US"}.
PRIMARY_URL: Final[str] = "http://api.country.is/"
# Резервные проверки — используются при ЛЮБОЙ ошибке или непригодном ответе предыдущей.
FALLBACK_ICANHAZIP_URL: Final[str] = "http://icanhazip.com"
FALLBACK_HTTPBIN_URL: Final[str] = "http://httpbin.org/ip"

DEFAULT_TIMEOUT: Final[float] = 5.0
MIN_TIMEOUT: Final[float] = 1.0
MAX_TIMEOUT: Final[float] = 60.0

DEFAULT_CONCURRENCY: Final[int] = 250
MIN_CONCURRENCY: Final[int] = 50
MAX_CONCURRENCY: Final[int] = 500

UNKNOWN_COUNTRY: Final[str] = "??"

_HEADERS: Final[dict[str, str]] = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36",
    "Accept": "*/*",
    "Connection": "close",
}


@dataclass(frozen=True, slots=True)
class ProxyResult:
    """Рабочий прокси с измеренным откликом."""

    proxy: str
    ptype: str
    ms: int
    country: str

    @property
    def detailed(self) -> str:
        """Строка для detailed-файла: ``ip:port | 142ms | DE``."""
        return f"{self.proxy} | {self.ms}ms | {self.country}"


@dataclass(slots=True)
class CheckReport:
    """Итог проверки одного типа прокси."""

    ptype: str
    total: int
    checked: int
    elapsed: float
    results: list[ProxyResult] = field(default_factory=list)

    @property
    def valid(self) -> int:
        return len(self.results)

    @property
    def speed(self) -> float:
        """Средняя скорость проверки, прокси/сек."""
        return self.checked / self.elapsed if self.elapsed > 0 else 0.0


class _SpeedColumn(ProgressColumn):
    """Колонка «прокси/сек» на основе скользящей скорости rich."""

    def render(self, task: Task) -> Text:
        return Text(f"{task.speed or 0.0:6.0f} пр/сек", style="magenta")


def _silent_exception_handler(loop: asyncio.AbstractEventLoop, context: dict[str, Any]) -> None:
    """Гасит шум от «оборванных» сокетов (например WinError 10054 на Windows)."""
    return None


def _is_ip(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    try:
        ipaddress.ip_address(value.strip())
    except ValueError:
        return False
    return True


def _load_json(text: str) -> Any | None:
    try:
        return json.loads(text)
    except ValueError:
        return None


def _parse_country_is(text: str) -> str | None:
    """api.country.is: нужен JSON с корректным ``ip``; возвращает код страны (или ``??``)."""
    data = _load_json(text)
    if not isinstance(data, dict) or not _is_ip(data.get("ip")):
        return None
    country = data.get("country")
    if isinstance(country, str) and country.strip():
        return country.strip().upper()
    return UNKNOWN_COUNTRY


def _parse_icanhazip(text: str) -> str | None:
    """icanhazip.com: тело ответа — просто IP-адрес."""
    return UNKNOWN_COUNTRY if _is_ip(text.strip()) else None


def _parse_httpbin(text: str) -> str | None:
    """httpbin.org/ip: JSON вида ``{"origin": "1.2.3.4"}``."""
    data = _load_json(text)
    if isinstance(data, dict) and isinstance(data.get("origin"), str) and data["origin"].strip():
        return UNKNOWN_COUNTRY
    return None


@dataclass(frozen=True, slots=True)
class _Probe:
    """Один вариант проверочного запроса и разбор его ответа."""

    url: str
    parse: Callable[[str], str | None]


# Порядок важен: следующая проба выполняется только если предыдущая не дала валидного ответа.
_PROBES: Final[tuple[_Probe, ...]] = (
    _Probe(PRIMARY_URL, _parse_country_is),
    _Probe(FALLBACK_ICANHAZIP_URL, _parse_icanhazip),
    _Probe(FALLBACK_HTTPBIN_URL, _parse_httpbin),
)


class ProxyChecker:
    """Асинхронный чекер.

    HTTP-прокси проверяются штатным ``proxy=`` aiohttp через общий ``TCPConnector(limit=0, ssl=False)``
    (честная проверка обычного проксирования). SOCKS4/SOCKS5 — через ``aiohttp_socks.ProxyConnector``.
    """

    def __init__(
        self,
        timeout: float = DEFAULT_TIMEOUT,
        concurrency: int = DEFAULT_CONCURRENCY,
        console: Console | None = None,
    ) -> None:
        self.timeout: float = float(min(max(timeout, MIN_TIMEOUT), MAX_TIMEOUT))
        self.concurrency: int = min(max(int(concurrency), MIN_CONCURRENCY), MAX_CONCURRENCY)
        self.console: Console = console or Console()
        self._client_timeout = aiohttp.ClientTimeout(total=self.timeout)

        self.ptype: str = "http"
        self.total: int = 0
        self.checked: int = 0
        self._results: list[ProxyResult] = []
        self._started: float = 0.0
        self._finished: float | None = None

    # ------------------------------------------------------------------ публичный API

    def snapshot(self) -> CheckReport:
        """Текущее (в том числе частичное) состояние проверки, отсортированное по пингу."""
        end = self._finished if self._finished is not None else time.perf_counter()
        elapsed = max(end - self._started, 0.0) if self._started else 0.0
        return CheckReport(
            ptype=self.ptype,
            total=self.total,
            checked=self.checked,
            elapsed=elapsed,
            results=sorted(self._results, key=lambda item: item.ms),
        )

    async def check(
        self,
        proxies: list[str],
        ptype: str,
        results_list: list[ProxyResult] | None = None,
    ) -> CheckReport:
        """Проверяет список прокси одного типа и возвращает отчёт (валидные — от быстрых к медленным).

        ``results_list`` передаётся по ссылке: чекер добавляет найденные прокси прямо в него. Поэтому при
        ``KeyboardInterrupt`` / ``CancelledError`` всё, что найдено до прерывания, остаётся у вызывающего кода
        (список не пересоздаётся и не очищается внутри чекера).
        """
        if ptype not in PROXY_TYPES:
            raise ValueError(f"Неизвестный тип прокси: {ptype!r}")

        self.ptype = ptype
        self.total = len(proxies)
        self.checked = 0
        self._results = results_list if results_list is not None else []
        self._started = time.perf_counter()
        self._finished = None

        loop = asyncio.get_running_loop()
        previous_handler = loop.get_exception_handler()
        loop.set_exception_handler(_silent_exception_handler)

        connector = aiohttp.TCPConnector(limit=0, ssl=False, force_close=True, ttl_dns_cache=300)
        semaphore = asyncio.Semaphore(self.concurrency)
        pending: set[asyncio.Task[None]] = set()

        try:
            # rich.Progress — синхронный контекстный менеджер, поэтому он внешний.
            with self._make_progress() as progress:
                task_id = progress.add_task(f"Проверка {ptype.upper()}", total=self.total, valid=0)

                async with aiohttp.ClientSession(
                    connector=connector, timeout=self._client_timeout, trust_env=False
                ) as shared_session:

                    async def worker(proxy: str) -> None:
                        try:
                            result = await self._check_one(shared_session, proxy, ptype)
                            if result is not None:
                                self._results.append(result)
                            self.checked += 1
                            progress.update(task_id, advance=1, valid=len(self._results))
                        finally:
                            semaphore.release()

                    try:
                        # Семафор ограничивает и число живых задач — память не растёт на больших списках.
                        for proxy in proxies:
                            await semaphore.acquire()
                            task = asyncio.create_task(worker(proxy))
                            pending.add(task)
                            task.add_done_callback(pending.discard)
                        if pending:
                            await asyncio.gather(*tuple(pending))
                    except asyncio.CancelledError:
                        for task in tuple(pending):
                            task.cancel()
                        await asyncio.gather(*tuple(pending), return_exceptions=True)
                        raise
        finally:
            self._finished = time.perf_counter()
            loop.set_exception_handler(previous_handler)

        return self.snapshot()

    # ------------------------------------------------------------------ внутренности

    def _make_progress(self) -> Progress:
        return Progress(
            TextColumn("[bold cyan]{task.description}"),
            BarColumn(bar_width=None),
            MofNCompleteColumn(),
            TextColumn("• валидных: [bold green]{task.fields[valid]}[/]"),
            _SpeedColumn(),
            TimeElapsedColumn(),
            TimeRemainingColumn(),
            console=self.console,
            transient=False,
            refresh_per_second=10,
        )

    async def _check_one(
        self, shared_session: aiohttp.ClientSession, proxy: str, ptype: str
    ) -> ProxyResult | None:
        """Проверяет один прокси. Любая сетевая ошибка = нерабочий прокси, программа не падает."""
        try:
            # Страховочный потолок на все пробы одного прокси: не больше 2×таймаут + 1 с.
            return await asyncio.wait_for(
                self._probe(shared_session, proxy, ptype), timeout=self.timeout * 2 + 1
            )
        except (asyncio.TimeoutError, aiohttp.ClientError, ProxyError, OSError, ValueError, UnicodeError):
            return None
        except Exception:  # noqa: BLE001
            # Сторонние библиотеки иногда бросают нестандартные ошибки на мусорных ответах прокси.
            return None

    async def _probe(
        self, shared_session: aiohttp.ClientSession, proxy: str, ptype: str
    ) -> ProxyResult | None:
        if ptype == "http":
            return await self._run_probes(shared_session, f"http://{proxy}", proxy, ptype)

        connector = ProxyConnector.from_url(f"{ptype}://{proxy}", ssl=False, force_close=True)
        async with aiohttp.ClientSession(
            connector=connector, timeout=self._client_timeout, trust_env=False
        ) as session:
            return await self._run_probes(session, None, proxy, ptype)

    async def _run_probes(
        self,
        session: aiohttp.ClientSession,
        proxy_url: str | None,
        proxy: str,
        ptype: str,
    ) -> ProxyResult | None:
        """Перебирает пробы: country.is → icanhazip → httpbin.

        Переход к следующей пробе происходит при любой ошибке, не-200 или непригодном ответе, поэтому
        живой прокси не отбраковывается из-за недоступности или лимита одного GeoIP-сервиса.
        Валидным считается прокси, получивший HTTP 200 и корректный ответ хотя бы одной пробы.
        Пинг измеряется по успешному запросу.
        """
        for probe in _PROBES:
            started = time.perf_counter()
            try:
                status, text = await self._get_text(session, probe.url, proxy_url)
            except Exception:  # noqa: BLE001 — таймаут/ProxyError/ClientError/мусорный ответ → следующая проба
                continue
            if status != 200 or text is None:
                continue
            country = probe.parse(text)
            if country is not None:
                return ProxyResult(proxy, ptype, self._elapsed_ms(started), country)
        return None

    @staticmethod
    async def _get_text(
        session: aiohttp.ClientSession, url: str, proxy_url: str | None
    ) -> tuple[int, str | None]:
        async with session.get(url, proxy=proxy_url, headers=_HEADERS, allow_redirects=False) as response:
            status = response.status
            if status != 200:
                return status, None
            raw = await response.read()
        return status, raw.decode("utf-8", errors="ignore")

    @staticmethod
    def _elapsed_ms(started: float) -> int:
        return max(1, round((time.perf_counter() - started) * 1000))
