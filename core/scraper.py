"""Асинхронный парсер свежих публичных прокси из открытых raw-источников GitHub."""

from __future__ import annotations

import asyncio
import re
import ssl
from dataclasses import dataclass, field
from typing import Any, Final, Sequence

import aiohttp

PROXY_TYPES: Final[tuple[str, ...]] = ("http", "socks4", "socks5")

_RAW: Final[str] = "https://raw.githubusercontent.com"

HEADERS: Final[dict[str, str]] = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/124.0 Safari/537.36"
    ),
}

# ip:port. Lookbehind/lookahead не дают захватить «хвосты» вроде 1.2.3.4.5 или порт из 6+ цифр.
_PROXY_RE: Final[re.Pattern[str]] = re.compile(
    r"(?<![\d.])((?:\d{1,3}\.){3}\d{1,3}):(\d{1,5})(?!\d)"
)


@dataclass(frozen=True, slots=True)
class Source:
    """Один raw-список прокси на GitHub."""

    name: str
    ptype: str
    url: str


def _build_sources() -> tuple[Source, ...]:
    sources: list[Source] = []
    for ptype in PROXY_TYPES:
        sources.append(
            Source("TheSpeedX/PROXY-List", ptype, f"{_RAW}/TheSpeedX/PROXY-List/master/{ptype}.txt")
        )
        sources.append(
            Source("monosans/proxy-list", ptype, f"{_RAW}/monosans/proxy-list/main/proxies/{ptype}.txt")
        )
        sources.append(
            Source(
                "proxifly/free-proxy-list",
                ptype,
                f"{_RAW}/proxifly/free-proxy-list/main/proxies/protocols/{ptype}/data.txt",
            )
        )
        sources.append(
            Source("vakhov/fresh-proxy-list", ptype, f"{_RAW}/vakhov/fresh-proxy-list/master/{ptype}.txt")
        )
    # hookzof публикует только SOCKS5.
    sources.append(Source("hookzof/socks5_list", "socks5", f"{_RAW}/hookzof/socks5_list/master/proxy.txt"))
    return tuple(sources)


SOURCES: Final[tuple[Source, ...]] = _build_sources()


@dataclass(slots=True)
class SourceStat:
    """Статистика по одному источнику."""

    source: str
    ptype: str
    found: int
    ok: bool


@dataclass(slots=True)
class ScrapeReport:
    """Итог парсинга: уникальные прокси по типам и статистика источников."""

    proxies: dict[str, list[str]] = field(default_factory=dict)
    stats: list[SourceStat] = field(default_factory=list)

    @property
    def raw_total(self) -> int:
        """Сколько адресов найдено до дедупликации."""
        return sum(stat.found for stat in self.stats)

    @property
    def unique_total(self) -> int:
        """Сколько уникальных адресов получилось после дедупликации."""
        return sum(len(items) for items in self.proxies.values())


def _is_valid_endpoint(host: str, port: str) -> bool:
    octets = host.split(".")
    if len(octets) != 4 or any(int(octet) > 255 for octet in octets):
        return False
    return 1 <= int(port) <= 65535


def extract_proxies(text: str) -> list[str]:
    """Достаёт из текста все ``ip:port`` (с любыми префиксами вроде ``http://``) без дублей."""
    found: list[str] = []
    for host, port in _PROXY_RE.findall(text):
        if _is_valid_endpoint(host, port):
            normalized_host = ".".join(str(int(octet)) for octet in host.split("."))
            found.append(f"{normalized_host}:{int(port)}")
    return list(dict.fromkeys(found))


def _build_ssl_context() -> Any:
    """Использует certifi, если он установлен (помогает на macOS без сертификатов), иначе системные."""
    try:
        import certifi  # type: ignore[import-not-found]

        return ssl.create_default_context(cafile=certifi.where())
    except (ImportError, OSError):
        return True


async def _fetch_text(session: aiohttp.ClientSession, url: str, retries: int = 2) -> str | None:
    """Скачивает текст по URL с несколькими попытками. Возвращает ``None`` при неудаче."""
    for attempt in range(retries + 1):
        try:
            async with session.get(url) as response:
                if response.status == 200:
                    return await response.text(errors="ignore")
        except (asyncio.TimeoutError, aiohttp.ClientError, OSError):
            pass
        if attempt < retries:
            await asyncio.sleep(0.8 * (attempt + 1))
    return None


async def scrape(types: Sequence[str], timeout: float = 20.0) -> ScrapeReport:
    """Параллельно качает списки всех источников для выбранных типов и дедуплицирует их."""
    wanted = [ptype for ptype in PROXY_TYPES if ptype in types]
    sources = [source for source in SOURCES if source.ptype in wanted]

    connector = aiohttp.TCPConnector(limit=16, ssl=_build_ssl_context())
    client_timeout = aiohttp.ClientTimeout(total=timeout)
    async with aiohttp.ClientSession(
        connector=connector, timeout=client_timeout, headers=HEADERS, trust_env=False
    ) as session:
        texts = await asyncio.gather(*(_fetch_text(session, source.url) for source in sources))

    report = ScrapeReport()
    collected: dict[str, list[str]] = {ptype: [] for ptype in wanted}
    for source, text in zip(sources, texts):
        if text is None:
            report.stats.append(SourceStat(source.name, source.ptype, 0, False))
            continue
        items = extract_proxies(text)
        collected[source.ptype].extend(items)
        report.stats.append(SourceStat(source.name, source.ptype, len(items), True))

    for ptype, items in collected.items():
        report.proxies[ptype] = list(dict.fromkeys(items))
    return report
