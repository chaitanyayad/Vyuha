"""Provenance tracing: given a span of text the agent produced, work out which
prior tool outputs it came from.

The agent tells us its `derived_from` in the intent, but we never rely on that
-- an agent under injection is exactly the agent whose self-report we cannot
trust. Everything here is computed by the gateway from the text itself.

Three independent matchers, cheapest first:

  verbatim    a >=24-char window of a prior output appears in the new text
  shingle     5-gram overlap over content words, catches light paraphrase
  identifier  a distinctive token (email address, salary figure, employee id)
              appears in both
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from .contract import Origin, ToolResult

WORD = re.compile(r"[A-Za-z0-9@._$%_-]+")

IDENTIFIER_PATTERNS = (
    re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b"),          # email addresses
    re.compile(r"\b(?:EMP|REQ|INV|PRJ)-?\d{3,}\b", re.I),   # record ids
    re.compile(r"[$₹]\s?\d[\d,]{3,}(?:\.\d+)?"),            # money
    re.compile(r"\bhttps?://[^\s\"'<>)]+"),                 # urls
)

STOP = frozenset(
    """the a an and or of to for in on at by with from as is are was were be been being this
    that these those it its we you they he she i not no do does did have has had will would
    can could should please your our their my me us them if then than so but about into over
    under all any each more most other some such only own same too very just now here there
    what which who whom when where why how""".split()
)

MIN_VERBATIM = 24
SHINGLE_N = 5
SHINGLE_HIT = 2  # distinct 5-grams shared before we call it a match


@dataclass(frozen=True)
class Match:
    output_id: str
    source: str
    origin: Origin
    method: str
    excerpt: str
    confidence: int

    @property
    def tainted(self) -> bool:
        return not self.origin.trusted


def normalize(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip().lower()


def content_words(text: str) -> list[str]:
    return [w for w in WORD.findall(text.lower()) if len(w) > 2 and w not in STOP]


def terms(text: str) -> set[str]:
    """Content words plus the pieces of compound tokens.

    `send_email` and `priya.nair@acme-internal.com` are single tokens to the
    matcher, which is right for provenance but wrong for topical comparison --
    a goal that says "email Priya" would otherwise share nothing with an
    intent that does exactly that. Used for goal drift only; the shingle
    matcher keeps the unsplit tokens.
    """
    out: set[str] = set()
    for word in content_words(text):
        out.add(word)
        for part in re.split(r"[._@%-]+", word):
            if len(part) > 2 and part not in STOP:
                out.add(part)
    return out


def shingles(words: list[str], n: int = SHINGLE_N) -> set[tuple[str, ...]]:
    if len(words) < n:
        return {tuple(words)} if words else set()
    return {tuple(words[i : i + n]) for i in range(len(words) - n + 1)}


def identifiers(text: str) -> set[str]:
    found: set[str] = set()
    for pat in IDENTIFIER_PATTERNS:
        found.update(m.group(0).strip().lower() for m in pat.finditer(text))
    return found


def _verbatim(haystack: str, needle_source: str) -> str | None:
    """Longest-ish shared window, found by sliding a fixed window. Outputs are
    kilobytes at most, so this stays well inside the latency budget."""
    src = normalize(needle_source)
    if len(src) < MIN_VERBATIM:
        return src if src and src in haystack else None
    best: str | None = None
    step = 8
    for i in range(0, len(src) - MIN_VERBATIM + 1, step):
        window = src[i : i + MIN_VERBATIM]
        if window in haystack:
            # grow the window to report something a human can recognise
            end = i + MIN_VERBATIM
            while end < len(src) and src[i:end + 1] in haystack:
                end += 1
            candidate = src[i:end]
            if best is None or len(candidate) > len(best):
                best = candidate
    return best


def match_one(text: str, output: ToolResult) -> Match | None:
    """Best evidence that `text` derives from `output`, or None."""
    hay = normalize(text)
    if not hay:
        return None

    span = _verbatim(hay, output.value)
    if span:
        conf = min(100, 60 + len(span) // 4)
        return Match(output.id, output.source, output.origin, "verbatim", _excerpt(span), conf)

    shared_ids = identifiers(text) & identifiers(output.value)
    if shared_ids:
        conf = min(95, 55 + 10 * len(shared_ids))
        return Match(
            output.id, output.source, output.origin, "identifier",
            ", ".join(sorted(shared_ids)[:4]), conf,
        )

    overlap = shingles(content_words(text)) & shingles(content_words(output.value))
    if len(overlap) >= SHINGLE_HIT:
        conf = min(90, 40 + 8 * len(overlap))
        sample = " ".join(sorted(overlap)[0])
        return Match(output.id, output.source, output.origin, "shingle", _excerpt(sample), conf)

    return None


def trace(text: str, outputs: dict[str, ToolResult] | list[ToolResult]) -> list[Match]:
    """Every prior output this text can be shown to derive from, strongest first."""
    pool = outputs.values() if isinstance(outputs, dict) else outputs
    found = [m for m in (match_one(text, o) for o in pool) if m is not None]
    return sorted(found, key=lambda m: -m.confidence)


def _excerpt(s: str, width: int = 90) -> str:
    s = re.sub(r"\s+", " ", s).strip()
    return s if len(s) <= width else s[: width - 1] + "…"
