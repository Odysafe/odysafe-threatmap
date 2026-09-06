"""Deterministic presentation helpers for Excel and terminal output."""

import html
import re
from collections.abc import Sequence
from typing import Any

from odysafe_threatmap.domain.models import NOT_AVAILABLE

_MARKDOWN_LINK = re.compile(r"\[([^\]]+)\]\([^)]*\)")
_HTML_TAG = re.compile(r"<[^>]+>")
_CITATION = re.compile(r"\s*\(Citation:\s*[^)]*\)", re.IGNORECASE)
_WHITESPACE = re.compile(r"\s+")
_IOC_TYPES = {
    "fqdn": "Domaine",
    "ipv4": "IPv4",
    "ipv6": "IPv6",
    "url": "URL",
    "email": "E-mail",
    "md5": "MD5",
    "sha1": "SHA-1",
    "sha256": "SHA-256",
    "sha512": "SHA-512",
    "cve": "CVE",
}


def clean_attack_text(text: str | None) -> str:
    """Mechanically remove markup, citations, and excess whitespace without paraphrasing."""
    if not text:
        return NOT_AVAILABLE
    value = _MARKDOWN_LINK.sub(r"\1", html.unescape(text))
    value = _HTML_TAG.sub(" ", value)
    value = _CITATION.sub("", value)
    return _WHITESPACE.sub(" ", value).strip() or NOT_AVAILABLE


def truncate_display_text(text: str | None, max_chars: int) -> str:
    """Clean and strictly truncate visible text at a word boundary when possible."""
    if max_chars < 1:
        raise ValueError("max_chars must be positive.")
    value = clean_attack_text(text)
    if len(value) <= max_chars:
        return value
    if max_chars == 1:
        return "…"
    cutoff = value[: max_chars - 1].rsplit(" ", 1)[0]
    return f"{cutoff or value[: max_chars - 1]}…"


def format_list(values: Sequence[str] | None, max_items: int | None = None) -> str:
    """Format ordered, unique display values with a visual-only item cap."""
    unique = list(dict.fromkeys(value.strip() for value in values or () if value and value.strip()))
    if not unique:
        return NOT_AVAILABLE
    if max_items is not None and len(unique) > max_items:
        return " • ".join([*unique[:max_items], f"+ {len(unique) - max_items} autres"])
    return " • ".join(unique)


def format_na(value: object | None) -> str:
    """Return the canonical missing-value display token."""
    return NOT_AVAILABLE if value is None or value == "" else str(value)


def format_yes_no(value: bool | None) -> str:
    """Display boolean values using French analyst-facing labels."""
    return "Oui" if value is True else "Non" if value is False else NOT_AVAILABLE


def format_ioc_type(value: str) -> str:
    """Translate only known internal IOC type labels."""
    return _IOC_TYPES.get(value.casefold(), value)


def safe_display_string(value: Any | None) -> str:
    """Return a safe, deterministic display string without changing source data."""
    return format_na(value)
