"""The six tools.  (T3)

Every return value is wrapped in a ToolResult carrying its Origin, which is
the only reason Ring 1 has anything to work with. A tool that forgets to label
its output is a hole in the gateway, so the labelling happens here, once, at
the boundary -- not in the agent.
"""

from __future__ import annotations

import json
from typing import Any, Callable

from pydantic import BaseModel, Field

from gateway.contract import Origin, ToolResult
from sandbox.env import ENV, CorpEnv


class ReadEmailArgs(BaseModel):
    email_id: str | None = None
    query: str | None = None


class SearchDocsArgs(BaseModel):
    query: str
    limit: int = Field(default=3, ge=1, le=8)


class ReadFileArgs(BaseModel):
    path: str


class DbQueryArgs(BaseModel):
    sql: str


class SendEmailArgs(BaseModel):
    to: str
    subject: str = ""
    body: str = ""


class HttpPostArgs(BaseModel):
    url: str
    payload: str = ""


def _table(rows: list[dict[str, Any]]) -> str:
    if not rows:
        return "(0 rows)"
    cols = list(rows[0].keys())
    lines = [" | ".join(cols), "-|-".join("-" * len(c) for c in cols)]
    lines += [" | ".join(str(r.get(c, "")) for c in cols) for r in rows]
    lines.append(f"({len(rows)} rows)")
    return "\n".join(lines)


def read_email(args: ReadEmailArgs, env: CorpEnv = ENV, session_id: str = "") -> ToolResult:
    email = None
    if args.email_id:
        email = env.email(args.email_id)
    elif args.query:
        q = args.query.lower()
        email = next(
            (e for e in env.emails if q in e["subject"].lower() or q in e["body"].lower()
             or q in e["from"].lower()),
            None,
        )
    else:
        listing = "\n".join(f"{e['id']}  {e['from']:<42}  {e['subject']}" for e in env.emails)
        return ToolResult(id="", tool="read_email", origin=Origin.EXTERNAL_MSG,
                          value=listing, source="inbox listing")
    if email is None:
        return ToolResult(id="", tool="read_email", origin=Origin.SYSTEM,
                          value="no matching message", source="inbox", ok=False)
    return ToolResult(
        id="", tool="read_email", origin=Origin.EXTERNAL_MSG,
        value=env.email_text(email), source=f"email:{email['id']} from {email['from']}",
        metadata={"email_id": email["id"], "from": email["from"]},
    )


def search_docs(args: SearchDocsArgs, env: CorpEnv = ENV, session_id: str = "") -> ToolResult:
    hits = env.search_documents(args.query, args.limit)
    if not hits:
        return ToolResult(id="", tool="search_docs", origin=Origin.SYSTEM,
                          value="no documents matched", source="doc store", ok=False)
    body = "\n\n".join(f"--- {d['path']} ---\n{d['body']}" for d in hits)
    return ToolResult(
        id="", tool="search_docs", origin=Origin.RETRIEVED_DOC, value=body,
        source="doc:" + ", ".join(d["path"] for d in hits),
        metadata={"paths": [d["path"] for d in hits]},
    )


def read_file(args: ReadFileArgs, env: CorpEnv = ENV, session_id: str = "") -> ToolResult:
    doc = env.document(args.path)
    if doc is None:
        return ToolResult(id="", tool="read_file", origin=Origin.SYSTEM,
                          value=f"no such file: {args.path}", source="fs", ok=False)
    return ToolResult(
        id="", tool="read_file", origin=Origin.RETRIEVED_DOC, value=doc["body"],
        source=f"doc:{doc['path']}", metadata={"path": doc["path"]},
    )


def db_query(args: DbQueryArgs, env: CorpEnv = ENV, session_id: str = "") -> ToolResult:
    try:
        rows = env.query(args.sql)
    except Exception as exc:
        return ToolResult(id="", tool="db_query", origin=Origin.SYSTEM,
                          value=f"query error: {exc}", source="corp-db", ok=False)
    return ToolResult(
        id="", tool="db_query", origin=Origin.TOOL_OUTPUT, value=_table(rows),
        source=f"db:{args.sql[:60]}", metadata={"rows": len(rows)},
    )


def send_email(args: SendEmailArgs, env: CorpEnv = ENV, session_id: str = "") -> ToolResult:
    d = env.deliver_email(args.to, args.subject, args.body, session_id=session_id)
    return ToolResult(
        id="", tool="send_email", origin=Origin.SYSTEM,
        value=f"delivered to outbound log: {d.summary()}", source="mail sink",
        metadata={"to": args.to},
    )


def http_post(args: HttpPostArgs, env: CorpEnv = ENV, session_id: str = "") -> ToolResult:
    d = env.deliver_http(args.url, args.payload, session_id=session_id)
    return ToolResult(
        id="", tool="http_post", origin=Origin.SYSTEM,
        value=f"posted to outbound log: {d.summary()}", source="http sink",
        metadata={"url": args.url},
    )


SCHEMAS: dict[str, type[BaseModel]] = {
    "read_email": ReadEmailArgs,
    "search_docs": SearchDocsArgs,
    "read_file": ReadFileArgs,
    "db_query": DbQueryArgs,
    "send_email": SendEmailArgs,
    "http_post": HttpPostArgs,
}

REGISTRY: dict[str, Callable[..., ToolResult]] = {
    "read_email": read_email,
    "search_docs": search_docs,
    "read_file": read_file,
    "db_query": db_query,
    "send_email": send_email,
    "http_post": http_post,
}


def execute(tool: str, arguments: dict[str, Any], env: CorpEnv = ENV,
            session_id: str = "") -> ToolResult:
    if tool not in REGISTRY:
        return ToolResult(id="", tool=tool, origin=Origin.SYSTEM,
                          value=f"unknown tool {tool}", source="executor", ok=False)
    parsed = SCHEMAS[tool].model_validate(arguments)
    return REGISTRY[tool](parsed, env=env, session_id=session_id)


def describe() -> str:
    return json.dumps(
        {name: model.model_json_schema() for name, model in SCHEMAS.items()},
        indent=2,
    )
