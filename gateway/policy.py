"""Ring 3 policy: YAML -> Pydantic.

Deliberately boring and deterministic. This is the ring whose behaviour can be
proved from a file, so the file has to stay readable.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, Field

from .settings import POLICY_PATH


def hostname(url: str) -> str:
    """Authority of a URL, with userinfo stripped.

    `https://intranet.acme-internal.com@collector.exfil-node.net/ingest` has
    hostname `collector.exfil-node.net`, not the reassuring string in front of
    the '@'. Argument smuggling lives in exactly this gap.
    """
    rest = re.sub(r"^\w+://", "", url.strip()).split("/")[0].split("?")[0]
    authority = rest.rsplit("@", 1)[-1]
    return authority.split(":")[0].strip().lower()


class ArgumentRule(BaseModel):
    field: str
    must_match_domain: list[str] | None = None
    must_match_host: list[str] | None = None
    deny_patterns: list[str] = Field(default_factory=list)
    max_len: int | None = None

    # "This field may not carry untrusted data across the trust boundary."
    # Untrusted data going to an *internal* destination is ordinary work
    # (summarise a doc, mail it to a colleague) and stays allowed -- that
    # distinction is what keeps the false-positive rate survivable.
    deny_tainted_egress: bool = False

    def domains_ok(self, value: str) -> bool:
        if self.must_match_domain is None:
            return True
        targets = [t.strip() for t in re.split(r"[,;\s]+", value) if t.strip()]
        return bool(targets) and all(
            any(t.lower().endswith(d.lower()) for d in self.must_match_domain) for t in targets
        )

    def host_ok(self, value: str) -> bool:
        if self.must_match_host is None:
            return True
        host = hostname(value)
        return any(host == h.lower() or host.endswith("." + h.lower()) for h in self.must_match_host)


class ToolPolicy(BaseModel):
    scopes: list[str] = Field(default_factory=list)
    requires_trust: int = 0
    argument_rules: list[ArgumentRule] = Field(default_factory=list)
    deny_patterns: list[str] = Field(default_factory=list)
    rate_limit: int | None = None

    # Sinks send data out, write, or spend. Ring 1 downgrades any sink call
    # that derives from untrusted content.
    sink: bool = False
    # Argument naming the far end of a sink call, e.g. "to" / "url".
    destination_field: str | None = None
    # Holds a credential worth confusing the deputy about. Ring 2's
    # confused-deputy check only applies here: "the agent read a colleague's
    # email and then searched the doc store" is how work happens, not an
    # incident, and firing on it would make the signal worthless.
    privileged: bool = False
    # Which origin label this tool stamps on its output, if it reads the world.
    emits_origin: Literal["TOOL_OUTPUT", "RETRIEVED_DOC", "EXTERNAL_MSG"] = "TOOL_OUTPUT"


class Policy(BaseModel):
    version: int = 1
    internal_domains: list[str] = Field(default_factory=list)
    internal_hosts: list[str] = Field(default_factory=list)
    trust: dict[str, int] = Field(default_factory=dict)
    tools: dict[str, ToolPolicy] = Field(default_factory=dict)

    def for_tool(self, tool: str) -> ToolPolicy | None:
        return self.tools.get(tool)

    def is_sink(self, tool: str) -> bool:
        p = self.tools.get(tool)
        return bool(p and p.sink)

    def is_internal_destination(self, value: str) -> bool:
        v = value.strip().lower()
        if "@" in v and "://" not in v and "/" not in v:
            return any(v.endswith(d.lower()) for d in self.internal_domains)
        host = hostname(v)
        return any(host == h.lower() or host.endswith("." + h.lower()) for h in self.internal_hosts)

    def penalty(self, key: str, default: int) -> int:
        return int(self.trust.get(key, default))


def load_policy(path: Path | str | None = None) -> Policy:
    path = Path(path or POLICY_PATH)
    with path.open("r", encoding="utf-8") as fh:
        raw: dict[str, Any] = yaml.safe_load(fh) or {}
    return Policy.model_validate(raw)


_cache: dict[str, Policy] = {}


def policy(path: Path | str | None = None) -> Policy:
    key = str(path or POLICY_PATH)
    if key not in _cache:
        _cache[key] = load_policy(key)
    return _cache[key]


def reload_policy() -> Policy:
    _cache.clear()
    return policy()
