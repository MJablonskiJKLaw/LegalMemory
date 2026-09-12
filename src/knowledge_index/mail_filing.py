"""Caller-authorized, idempotent matter filing over the existing MCP transport.

Staging is bounded SQL custody, not a caller-provided filesystem path. Hash sharing
never shares a document or matter authorization boundary.
"""
from __future__ import annotations

import base64
import hashlib
import io
import json
import os
from datetime import UTC, datetime, timedelta
from typing import Literal
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, model_validator
from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from knowledge_index.artifacts import LocalArtifactStore
from knowledge_index.auth import Identity
from knowledge_index.db.models import (
    Blob, Document, DocumentVersion, DocumentVersionSource, MailFiling,
    MailFilingChunk, Matter, MatterAssignment, ProcessingState, Project,
    ProjectGrant, Source, SourceObject,
)
from knowledge_index.permissions import AccessService
from knowledge_index.taxonomies import PIPELINE_STAGE_ORDER, WAITING_FOR_PREVIOUS_STAGE

MAX_BYTES = 96 * 1024 * 1024
CHUNK_BYTES = 256 * 1024


class FilingPart(BaseModel):
    model_config = ConfigDict(extra="forbid")
    kind: Literal["original", "attachment"]
    filename: str = Field(min_length=1, max_length=512)
    mime_type: str = Field(min_length=1, max_length=255)
    size: int = Field(ge=0, le=64 * 1024 * 1024)
    sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    content_id: str | None = Field(default=None, max_length=1024)


class FilingManifest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    version: Literal[1]
    source_account: str = Field(min_length=1, max_length=4096)
    provider: Literal["gmail", "graph", "imap", "archive"]
    locator: dict
    headers: dict[str, list[str]]
    received_at: str | None = Field(default=None, max_length=100)
    captured_at: str = Field(max_length=100)
    parts: list[FilingPart] = Field(min_length=1, max_length=101)

    @model_validator(mode="after")
    def bounded(self):
        if self.parts[0].kind != "original" or any(p.kind == "original" for p in self.parts[1:]):
            raise ValueError("exactly one original must be first")
        if sum(p.size for p in self.parts) > MAX_BYTES:
            raise ValueError("filing exceeds size limit")
        if len(json.dumps(self.locator).encode()) > 32768 or len(json.dumps(self.headers).encode()) > 65536:
            raise ValueError("provenance exceeds size limit")
        if len(self.headers) > 100 or any(len(name) > 100 or len(values) > 100 for name, values in self.headers.items()):
            raise ValueError("headers exceed count limit")
        datetime.fromisoformat(self.captured_at.replace("Z", "+00:00"))
        if self.received_at:
            datetime.fromisoformat(self.received_at.replace("Z", "+00:00"))
        return self


def _canonical(value: dict) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def _sync_blob_publication(path):
    """Persist the file's directory entry and every newly created ancestor link."""
    # The appliance uses a local POSIX filesystem. Failure prevents the SQL receipt
    # commit; shared content addresses are deliberately never removed on rollback.
    for directory in path.parents:
        descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)


class MailFilingService:
    def __init__(self, session: Session, artifact_store: LocalArtifactStore, identity: Identity):
        self.session, self.artifacts, self.identity = session, artifact_store, identity
        self.access = AccessService(session)
        self.principals = self.access.resolve_principals(set(identity.principals))

    def _matter(self, matter_id: str, *, write: bool) -> Matter:
        matter = self.session.get(Matter, matter_id)
        project = self.session.get(Project, matter.project_id) if matter and matter.project_id else None
        if not matter or not project or project.status != "active":
            raise PermissionError("filing destination unavailable")
        grants = list(self.session.scalars(select(ProjectGrant).where(
            ProjectGrant.project_id == project.id,
            ProjectGrant.principal.in_(sorted(self.principals)),
        )))
        if any(g.effect == "deny" for g in grants):
            raise PermissionError("filing destination unavailable")
        if write and not self.access.is_admin(self.principals) and not any(
            g.effect == "allow" and g.role in {"editor", "admin", "owner"} for g in grants
        ):
            raise PermissionError("filing destination unavailable")
        return matter

    def destinations(self, *, offset: int = 0, limit: int = 50) -> dict:
        if not 0 <= offset <= 2147483647 or not 1 <= limit <= 100:
            raise ValueError("invalid page")
        grant = select(ProjectGrant.project_id).where(
            ProjectGrant.project_id == Matter.project_id,
            ProjectGrant.principal.in_(sorted(self.principals)),
        )
        allowed = grant.where(ProjectGrant.effect == "allow", ProjectGrant.role.in_(["editor", "admin", "owner"])).exists()
        denied = grant.where(ProjectGrant.effect == "deny").exists()
        query = select(Matter).join(Project, Project.id == Matter.project_id).where(
            Project.status == "active", ~denied,
            True if self.access.is_admin(self.principals) else allowed,
        ).order_by(Matter.id).offset(offset).limit(limit + 1)
        rows = list(self.session.scalars(query))
        visible = [{"id": matter.id, "title": matter.title, "project_id": matter.project_id} for matter in rows[:limit]]
        return {"version": 1, "principal_key": hashlib.sha256(self.identity.subject.encode()).hexdigest(), "results": visible, "next_offset": offset + limit if len(rows) > limit else None}

    def purge_expired(self) -> None:
        expired = select(MailFiling.id).where(MailFiling.state == "uploading", MailFiling.expires_at < datetime.now(UTC))
        self.session.execute(delete(MailFilingChunk).where(MailFilingChunk.filing_id.in_(expired)))
        self.session.execute(delete(MailFiling).where(MailFiling.id.in_(expired)))

    def _pending(self, filing_id: str) -> MailFiling:
        row = self.session.scalar(select(MailFiling).where(MailFiling.id == filing_id).with_for_update())
        if not row or row.actor_id != self.identity.subject:
            raise PermissionError("filing unavailable")
        self._matter(row.matter_id, write=True)
        if row.project_id != self.session.get(Matter, row.matter_id).project_id:
            raise PermissionError("filing destination changed")
        if row.state != "committed" and row.expires_at.replace(tzinfo=UTC) < datetime.now(UTC):
            raise ValueError("filing upload expired")
        return row

    def _progress(self, row: MailFiling) -> dict:
        if row.state == "committed":
            return self.read(row.id)
        manifest = FilingManifest.model_validate(row.manifest)
        offsets = []
        for ordinal, _part in enumerate(manifest.parts):
            offset = 0
            for chunk_offset, size in self.session.execute(select(MailFilingChunk.offset, func.length(MailFilingChunk.data)).where(MailFilingChunk.filing_id == row.id, MailFilingChunk.part == ordinal).order_by(MailFilingChunk.offset)):
                if chunk_offset != offset:
                    raise ValueError("invalid staged chunk order")
                offset += size
            offsets.append(offset)
        return {"id": row.id, "state": "uploading", "offsets": offsets}

    def begin(self, matter_id: str, replay_key: str, supplied: dict) -> dict:
        if not replay_key or len(replay_key) > 100:
            raise ValueError("invalid replay key")
        matter = self._matter(matter_id, write=True)
        if self.session.bind is not None and self.session.bind.dialect.name == "postgresql":
            self.session.execute(select(func.pg_advisory_xact_lock(1480001)))
        manifest = FilingManifest.model_validate(supplied).model_dump()
        digest = hashlib.sha256(_canonical(manifest)).hexdigest()
        self.purge_expired()
        old = self.session.scalar(select(MailFiling).where(MailFiling.matter_id == matter_id, MailFiling.actor_id == self.identity.subject, MailFiling.replay_key == replay_key))
        if old:
            if old.manifest_hash != digest:
                raise ValueError("filing replay differs")
            return self._progress(old)
        count = self.session.scalar(select(func.count()).select_from(MailFiling).where(MailFiling.actor_id == self.identity.subject, MailFiling.state == "uploading"))
        total = self.session.scalar(select(func.count()).select_from(MailFiling).where(MailFiling.state == "uploading"))
        if count >= 2 or total >= 64:
            raise ValueError("finish or cancel existing uploads first")
        row = MailFiling(id=str(uuid4()), matter_id=matter.id, project_id=matter.project_id, actor_id=self.identity.subject, replay_key=replay_key, manifest_hash=digest, manifest=manifest, state="uploading", expires_at=datetime.now(UTC) + timedelta(hours=24))
        self.session.add(row)
        self.session.flush()
        return self._progress(row)

    def chunk(self, filing_id: str, part: int, offset: int, data: str) -> dict:
        row = self._pending(filing_id)
        if row.state != "uploading":
            return self.read(row.id)
        manifest = FilingManifest.model_validate(row.manifest)
        if not 0 <= part < len(manifest.parts) or offset < 0 or len(data) > (CHUNK_BYTES * 4 // 3 + 4):
            raise ValueError("invalid chunk")
        raw = base64.b64decode(data, validate=True)
        if not raw or len(raw) > CHUNK_BYTES or base64.b64encode(raw).decode() != data:
            raise ValueError("invalid chunk")
        old = self.session.get(MailFilingChunk, (filing_id, part, offset))
        if old:
            if old.data != raw:
                raise ValueError("chunk replay differs")
            return self._progress(row)
        progress = self._progress(row)
        if progress["offsets"][part] != offset or offset + len(raw) > manifest.parts[part].size:
            raise ValueError("chunk offset differs")
        self.session.add(MailFilingChunk(filing_id=filing_id, part=part, offset=offset, data=raw))
        self.session.flush()
        return self._progress(row)

    def commit(self, filing_id: str) -> dict:
        row = self._pending(filing_id)
        if row.state == "committed":
            return self.read(row.id)
        manifest = FilingManifest.model_validate(row.manifest)
        if self._progress(row)["offsets"] != [p.size for p in manifest.parts]:
            raise ValueError("filing is incomplete")
        # Verify every declared component before publishing any artifact or association.
        for ordinal, part in enumerate(manifest.parts):
            digest = hashlib.sha256()
            for data in self.session.scalars(select(MailFilingChunk.data).where(MailFilingChunk.filing_id == row.id, MailFilingChunk.part == ordinal).order_by(MailFilingChunk.offset)):
                digest.update(data)
            if digest.hexdigest() != part.sha256:
                raise ValueError("filing hash differs")
        source = Source(id=str(uuid4()), project_id=row.project_id, kind="mail_filing", display_name="Filed mail", status="paused", config={"filing_id": row.id}, provider="native")
        self.session.add(source)
        self.session.flush()
        parts = []
        for ordinal, part in enumerate(manifest.parts):
            data = b"".join(chunk.data for chunk in self.session.scalars(select(MailFilingChunk).where(MailFilingChunk.filing_id == row.id, MailFilingChunk.part == ordinal).order_by(MailFilingChunk.offset)))
            if len(data) != part.size or hashlib.sha256(data).hexdigest() != part.sha256:
                raise ValueError("filing hash differs")
            stored = self.artifacts.put_blob(io.BytesIO(data), max_bytes=MAX_BYTES)
            _sync_blob_publication(stored.path)
            # An existing content address may have suffered corruption. Never publish it blindly.
            if stored.path.stat().st_size != part.size or hashlib.sha256(stored.path.read_bytes()).hexdigest() != part.sha256:
                raise ValueError("stored original failed verification")
            if not self.session.get(Blob, part.sha256):
                self.session.add(Blob(content_hash=part.sha256, size_bytes=part.size, mime_sniffed=part.mime_type, cached_path=str(stored.path)))
                self.session.flush()
            provenance = {"kind": "deliberate_mail_filing", "filing_id": row.id, "part": ordinal, "manifest_hash": row.manifest_hash, "source": row.manifest}
            document = Document(id=str(uuid4()), project_id=row.project_id, matter_id=row.matter_id, title=part.filename, provenance=provenance)
            obj = SourceObject(id=str(uuid4()), source_id=source.id, external_id=str(ordinal), name=part.filename, path=str(ordinal) + "/" + part.filename, content_hash=part.sha256, mime_type=part.mime_type, size_bytes=part.size, acl=None)
            self.session.add_all([document, obj])
            self.session.flush()
            version = DocumentVersion(id=str(uuid4()), document_id=document.id, content_hash=part.sha256, ordinal=1, status="final", provenance=provenance)
            self.session.add(version)
            self.session.flush()
            self.session.add(DocumentVersionSource(version_id=version.id, source_object_id=obj.id))
            self.session.add(MatterAssignment(source_object_id=obj.id, matter_id=row.matter_id, confidence=1, evidence=["Deliberate authorized filing"], producer_version="mail-filing-v1"))
            for stage in PIPELINE_STAGE_ORDER:
                self.session.add(ProcessingState(source_object_id=obj.id, stage=stage.value, status="pending" if stage.value == "convert" else "done" if stage.value == "fetch" else "skipped", last_error=None if stage.value in {"fetch", "convert"} else {"reason": WAITING_FOR_PREVIOUS_STAGE}))
            parts.append({"ordinal": ordinal, "document_id": document.id, "version_id": version.id, "source_object_id": obj.id, "sha256": part.sha256, "size": part.size})
        row.source_id, row.state = source.id, "committed"
        row.receipt = {"id": row.id, "state": "committed", "matter_id": row.matter_id, "project_id": row.project_id, "manifest_hash": row.manifest_hash, "filed_at": datetime.now(UTC).isoformat(), "parts": parts, "ingestion": "queued"}
        self.session.execute(delete(MailFilingChunk).where(MailFilingChunk.filing_id == row.id))
        self.session.flush()
        return row.receipt

    def cancel(self, filing_id: str) -> dict:
        row = self._pending(filing_id)
        if row.state == "committed":
            raise ValueError("filed originals require the separate retention workflow")
        self.session.execute(delete(MailFilingChunk).where(MailFilingChunk.filing_id == row.id))
        self.session.delete(row)
        return {"id": filing_id, "state": "cancelled"}

    def read(self, filing_id: str) -> dict:
        row = self.session.get(MailFiling, filing_id)
        if not row or row.state != "committed" or not row.receipt:
            raise PermissionError("filing unavailable")
        matter = self._matter(row.matter_id, write=False)
        if matter.project_id != row.project_id:
            raise PermissionError("filing destination changed")
        versions = [part["version_id"] for part in row.receipt["parts"]]
        visible = set(self.session.scalars(select(DocumentVersion.id).join(Document).where(DocumentVersion.id.in_(versions), self.access.version_predicate(self.principals))))
        if visible != set(versions):
            raise PermissionError("filing unavailable")
        return row.receipt

    def authorized(self, filing_ids: list[str]) -> dict:
        if len(filing_ids) > 200 or any(len(item) > 36 for item in filing_ids):
            raise ValueError("too many filing IDs")
        receipts = []
        for filing_id in dict.fromkeys(filing_ids):
            try:
                receipt = self.read(filing_id)
                receipts.append({key: receipt[key] for key in ("id", "matter_id", "project_id", "manifest_hash")})
            except PermissionError:
                continue
        return {"receipts": receipts}
