"""Simulated mock tool execution for TraceGuard runtime.

Module 6 — Runtime Defense & Multi-Turn Episode Runner.
Member 2: Data & Interpretability Lead.

Executes simulated, safe, offline operations for all 9 synthetic tools defined
in tools.yaml:
- search_emails, read_email
- search_documents, read_document
- retrieve_notes, save_note
- draft_email, send_email
- read_private_file

Zero network access, zero external email sending, zero filesystem modifications.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping, Optional, Sequence

from traceguard.data.schema import ProvenanceLabel, SourceRecord


@dataclass(frozen=True)
class ToolResult:
    """Result of a simulated tool execution."""

    tool: str
    arguments: dict[str, Any]
    success: bool
    output: Any
    provenance: ProvenanceLabel
    executed: bool = True
    error: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool": self.tool,
            "arguments": dict(self.arguments),
            "success": self.success,
            "output": self.output,
            "provenance": self.provenance.value,
            "executed": self.executed,
            "error": self.error,
        }


class MockToolExecutor:
    """Simulated in-memory tool execution engine backed by episode source records."""

    def __init__(self) -> None:
        self._emails: dict[str, SourceRecord] = {}
        self._documents: dict[str, SourceRecord] = {}
        self._private_files: dict[str, SourceRecord] = {}
        self._notes: list[dict[str, Any]] = []
        self._drafts: list[dict[str, Any]] = []
        self._sent_emails: list[dict[str, Any]] = []

    def populate_from_source_records(
        self, records: Sequence[SourceRecord]
    ) -> None:
        """Index episode source records by type and identifier."""
        for rec in records:
            st = rec.source_type.lower()
            if st == "email":
                self._emails[rec.source_id] = rec
            elif st == "document":
                self._documents[rec.source_id] = rec
            elif st == "private_file" or "private" in st:
                # Index both by source_id and metadata path
                self._private_files[rec.source_id] = rec
                path = rec.metadata.get("path") or rec.metadata.get("filepath")
                if path:
                    self._private_files[str(path)] = rec
            else:
                # Generic fallback to document store
                self._documents[rec.source_id] = rec

    def execute(self, tool_name: str, arguments: dict[str, Any]) -> ToolResult:
        """Dispatch and simulate execution for the specified tool."""
        handler = getattr(self, f"_exec_{tool_name}", None)
        if handler is None:
            return ToolResult(
                tool=tool_name,
                arguments=arguments,
                success=False,
                output=None,
                provenance=ProvenanceLabel.UNKNOWN,
                executed=False,
                error=f"No simulation handler implemented for tool {tool_name!r}",
            )
        try:
            return handler(arguments)
        except Exception as exc:
            return ToolResult(
                tool=tool_name,
                arguments=arguments,
                success=False,
                output=None,
                provenance=ProvenanceLabel.UNKNOWN,
                executed=False,
                error=str(exc),
            )

    # 1. search_emails
    def _exec_search_emails(self, args: dict[str, Any]) -> ToolResult:
        query = str(args.get("query", "")).lower()
        limit = int(args.get("limit", 10)) if args.get("limit") is not None else 10

        matches: list[dict[str, Any]] = []
        out_prov = ProvenanceLabel.SYSTEM_CONFIG
        for s_id, rec in self._emails.items():
            if query in rec.content.lower() or query in s_id.lower():
                matches.append(
                    {
                        "email_id": s_id,
                        "subject": rec.metadata.get("subject", f"Email {s_id}"),
                        "sender": rec.metadata.get("sender", "unknown@corp.example.org"),
                        "snippet": rec.content[:120],
                    }
                )
                if rec.provenance in {
                    ProvenanceLabel.UNTRUSTED_EXTERNAL,
                    ProvenanceLabel.DERIVED_UNTRUSTED,
                }:
                    out_prov = rec.provenance
                if len(matches) >= limit:
                    break

        return ToolResult(
            tool="search_emails",
            arguments=args,
            success=True,
            output=matches,
            provenance=out_prov,
        )

    # 2. read_email
    def _exec_read_email(self, args: dict[str, Any]) -> ToolResult:
        email_id = str(args.get("email_id", "")).strip()
        rec = self._emails.get(email_id)
        if rec is None:
            return ToolResult(
                tool="read_email",
                arguments=args,
                success=False,
                output=f"Email {email_id!r} not found",
                provenance=ProvenanceLabel.UNKNOWN,
                error="Email not found",
            )
        return ToolResult(
            tool="read_email",
            arguments=args,
            success=True,
            output={
                "email_id": rec.source_id,
                "content": rec.content,
                "metadata": rec.metadata,
            },
            provenance=rec.provenance,
        )

    # 3. search_documents
    def _exec_search_documents(self, args: dict[str, Any]) -> ToolResult:
        query = str(args.get("query", "")).lower()
        limit = int(args.get("limit", 10)) if args.get("limit") is not None else 10
        scope = str(args.get("scope", "")).lower()

        matches: list[dict[str, Any]] = []
        out_prov = ProvenanceLabel.SYSTEM_CONFIG
        for s_id, rec in self._documents.items():
            if query in rec.content.lower() or query in s_id.lower() or query in str(rec.metadata).lower():
                matches.append(
                    {
                        "doc_id": s_id,
                        "title": rec.metadata.get("filename", s_id),
                        "snippet": rec.content[:120],
                    }
                )
                if rec.provenance in {
                    ProvenanceLabel.UNTRUSTED_EXTERNAL,
                    ProvenanceLabel.DERIVED_UNTRUSTED,
                }:
                    out_prov = rec.provenance
                if len(matches) >= limit:
                    break

        return ToolResult(
            tool="search_documents",
            arguments=args,
            success=True,
            output=matches,
            provenance=out_prov,
        )

    # 4. read_document
    def _exec_read_document(self, args: dict[str, Any]) -> ToolResult:
        doc_id = str(args.get("doc_id", "")).strip()
        rec = self._documents.get(doc_id)
        if rec is None:
            return ToolResult(
                tool="read_document",
                arguments=args,
                success=False,
                output=f"Document {doc_id!r} not found",
                provenance=ProvenanceLabel.UNKNOWN,
                error="Document not found",
            )
        return ToolResult(
            tool="read_document",
            arguments=args,
            success=True,
            output={
                "doc_id": rec.source_id,
                "content": rec.content,
                "metadata": rec.metadata,
            },
            provenance=rec.provenance,
        )

    # 5. retrieve_notes
    def _exec_retrieve_notes(self, args: dict[str, Any]) -> ToolResult:
        query = str(args.get("query", "")).lower()
        limit = int(args.get("limit", 10)) if args.get("limit") is not None else 10

        matching: list[dict[str, Any]] = []
        for n in self._notes:
            if query in n["content"].lower():
                matching.append(n)
                if len(matching) >= limit:
                    break

        return ToolResult(
            tool="retrieve_notes",
            arguments=args,
            success=True,
            output=matching,
            provenance=ProvenanceLabel.USER_AUTHORIZED,
        )

    # 6. save_note
    def _exec_save_note(self, args: dict[str, Any]) -> ToolResult:
        content = str(args.get("content", ""))
        note_id = f"note_{len(self._notes) + 1:03d}"
        note_record = {"note_id": note_id, "content": content}
        self._notes.append(note_record)
        return ToolResult(
            tool="save_note",
            arguments=args,
            success=True,
            output={"status": "saved", "note_id": note_id},
            provenance=ProvenanceLabel.USER_AUTHORIZED,
        )

    # 7. draft_email (sensitive)
    def _exec_draft_email(self, args: dict[str, Any]) -> ToolResult:
        to = str(args.get("to", ""))
        subject = str(args.get("subject", ""))
        body = str(args.get("body", ""))
        draft_record = {"to": to, "subject": subject, "body": body}
        self._drafts.append(draft_record)
        return ToolResult(
            tool="draft_email",
            arguments=args,
            success=True,
            output={"status": "draft_created", "to": to, "subject": subject},
            provenance=ProvenanceLabel.USER_AUTHORIZED,
        )

    # 8. send_email (sensitive)
    def _exec_send_email(self, args: dict[str, Any]) -> ToolResult:
        to = str(args.get("to", ""))
        subject = str(args.get("subject", ""))
        body = str(args.get("body", ""))
        sent_record = {"to": to, "subject": subject, "body": body}
        self._sent_emails.append(sent_record)
        return ToolResult(
            tool="send_email",
            arguments=args,
            success=True,
            output={"status": "sent", "to": to, "subject": subject},
            provenance=ProvenanceLabel.USER_AUTHORIZED,
        )

    # 9. read_private_file (sensitive)
    def _exec_read_private_file(self, args: dict[str, Any]) -> ToolResult:
        path = str(args.get("path", "")).strip()
        rec = self._private_files.get(path)
        if rec is not None:
            return ToolResult(
                tool="read_private_file",
                arguments=args,
                success=True,
                output={"path": path, "content": rec.content},
                provenance=rec.provenance,
            )
        # Default simulated restricted response
        return ToolResult(
            tool="read_private_file",
            arguments=args,
            success=True,
            output={"path": path, "content": f"[Simulated restricted content for {path}]"},
            provenance=ProvenanceLabel.SYSTEM_CONFIG,
        )
