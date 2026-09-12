"""Isolated synthetic storage/identity fixtures; never use live model or user data."""
import base64
import hashlib
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import sessionmaker

from knowledge_index.artifacts import LocalArtifactStore
from knowledge_index.auth import Identity
from knowledge_index.config import AppConfig
from knowledge_index.db.models import (
    Base, Blob, Document, DocumentVersion, MailFiling, MailFilingChunk,
    Matter, MatterAssignment, ProcessingState, Project, ProjectGrant, SourceObject,
)
from knowledge_index.mail_filing import MailFilingService
from knowledge_index.pipeline.runner import PipelineRunner

RAW = b'From: sender@example.test\r\nTo: owner@example.test\r\nSubject: Original\r\n\r\nOriginal body'
ATTACHMENT = b'original attachment bytes'

def identity(name):
    return Identity(subject=name, username=name, principals=frozenset({"user:" + name}))


def manifest(attachment=ATTACHMENT):
    return {"version": 1, "source_account": "synthetic", "provider": "gmail", "locator": {"messageId": "one"}, "headers": {"from": ["sender@example.test"]}, "captured_at": datetime.now(UTC).isoformat(), "parts": [{"kind": "original", "filename": "Original.eml", "mime_type": "message/rfc822", "size": len(RAW), "sha256": hashlib.sha256(RAW).hexdigest()}, {"kind": "attachment", "filename": "秘密.txt", "mime_type": "text/plain", "size": len(attachment), "sha256": hashlib.sha256(attachment).hexdigest()}]}


@pytest.fixture
def fixture(tmp_path):
    engine = create_engine("sqlite:///" + str(tmp_path / "store.sqlite"))
    Base.metadata.create_all(engine)
    factory = sessionmaker(engine)
    with factory.begin() as session:
        for number in (1, 2):
            session.add(Project(id=f"p{number}", key=f"p{number}", name="Project"))
            session.flush()
            session.add(Matter(id=f"m{number}", project_id=f"p{number}", title="Matter"))
        session.add_all([ProjectGrant(project_id="p1", principal="user:writer", effect="allow", role="editor"), ProjectGrant(project_id="p2", principal="user:writer", effect="allow", role="editor"), ProjectGrant(project_id="p1", principal="user:reader", effect="allow", role="viewer"), ProjectGrant(project_id="p2", principal="user:other", effect="allow", role="viewer")])
    yield factory, LocalArtifactStore(tmp_path / "artifacts")
    engine.dispose()


def service(session, artifacts, name="writer"):
    return MailFilingService(session, artifacts, identity(name))


def file(factory, artifacts, matter="m1", key="one", supplied=None):
    supplied = supplied or manifest()
    with factory.begin() as session:
        started = service(session, artifacts).begin(matter, key, supplied)
    for part, raw in enumerate((RAW, ATTACHMENT)):
        with factory.begin() as session:
            service(session, artifacts).chunk(started["id"], part, 0, base64.b64encode(raw).decode())
    with factory.begin() as session:
        return service(session, artifacts).commit(started["id"])


def scope(receipt):
    return {key: receipt[key] for key in ("id", "matter_id", "project_id", "manifest_hash")}

def test_write_is_explicit_and_deny_wins_read_and_write(fixture):
    factory, artifacts = fixture
    with factory.begin() as session:
        assert service(session, artifacts, "reader").destinations()["results"] == []
        with pytest.raises(PermissionError):
            service(session, artifacts, "reader").begin("m1", "one", manifest())
    receipt = file(factory, artifacts)
    with factory.begin() as session:
        assert service(session, artifacts, "reader").read(receipt["id"]) == receipt
        assert service(session, artifacts, "other").authorized([receipt["id"], "missing"])["receipts"] == []
        session.add(ProjectGrant(project_id="p1", principal="user:writer", effect="deny", role="viewer"))
    with factory.begin() as session:
        with pytest.raises(PermissionError):
            service(session, artifacts).read(receipt["id"])
        with pytest.raises(PermissionError):
            service(session, artifacts).begin("m1", "next", manifest())


def test_chunks_replay_restart_hash_verification_and_revocation(fixture):
    factory, artifacts = fixture
    supplied = manifest()
    with factory.begin() as session:
        started = service(session, artifacts).begin("m1", "one", supplied)
    with factory.begin() as session:
        current = service(session, artifacts)
        value = current.chunk(started["id"], 0, 0, base64.b64encode(RAW).decode())
        assert current.chunk(started["id"], 0, 0, base64.b64encode(RAW).decode()) == value
        with pytest.raises(ValueError):
            current.chunk(started["id"], 0, 1, base64.b64encode(RAW).decode())
    with factory.begin() as session:
        assert service(session, artifacts).begin("m1", "one", supplied)["offsets"] == [len(RAW), 0]
        service(session, artifacts).chunk(started["id"], 1, 0, base64.b64encode(b'x' * len(ATTACHMENT)).decode())
    with pytest.raises(ValueError), factory.begin() as session:
        service(session, artifacts).commit(started["id"])
    assert not list(artifacts.blob_root.rglob("*"))
    with factory.begin() as session:
        assert session.scalar(select(func.count()).select_from(Document)) == 0
        session.add(ProjectGrant(project_id="p1", principal="user:writer", effect="deny", role="viewer"))
    with pytest.raises(PermissionError), factory.begin() as session:
        service(session, artifacts).chunk(started["id"], 0, 0, base64.b64encode(RAW).decode())


def test_multiple_matters_share_bytes_never_document_scope_and_keep_pinned_ingestion(fixture):
    factory, artifacts = fixture
    supplied = manifest()
    first = file(factory, artifacts, supplied=supplied)
    second = file(factory, artifacts, "m2", supplied=supplied)
    with factory.begin() as session:
        assert session.scalar(select(func.count()).select_from(Blob)) == 2
        assert session.scalar(select(func.count()).select_from(Document)) == 4
        assert first["parts"][0]["document_id"] != second["parts"][0]["document_id"]
        assert service(session, artifacts, "reader").authorized([first["id"], second["id"]])["receipts"] == [scope(first)]
        assert service(session, artifacts).begin("m1", "one", supplied) == first
        assert service(session, artifacts).commit(first["id"]) == first
        assert session.scalar(select(func.count()).select_from(MailFilingChunk)) == 0
        object_id = first["parts"][0]["source_object_id"]
        runner = PipelineRunner(factory, AppConfig(artifact_dir=artifacts.root))
        state = session.scalar(select(ProcessingState).where(ProcessingState.source_object_id == object_id, ProcessingState.stage == "classify_matter"))
        assert runner._classify_matter(session, state).skip_reason is None
        assert runner._relate(session, state).skip_reason is None
        assert runner._file_entity_for_ref(session, object_id, {}) is None
        assert session.get(MatterAssignment, object_id).matter_id == "m1"
        session.get(SourceObject, object_id).deleted_at = datetime.now(UTC)
    with factory.begin() as session:
        assert service(session, artifacts).authorized([first["id"], second["id"]])["receipts"] == [scope(second)]


def test_expired_staging_is_bounded_and_reclaimed(fixture):
    factory, artifacts = fixture
    with factory.begin() as session:
        current = service(session, artifacts)
        first = current.begin("m1", "first", manifest())
        current.begin("m2", "second", manifest())
        with pytest.raises(ValueError):
            current.begin("m1", "third", manifest())
        current.chunk(first["id"], 0, 0, base64.b64encode(RAW).decode())
        for row in session.scalars(select(MailFiling)):
            row.expires_at = datetime.now(UTC) - timedelta(seconds=1)
    with factory.begin() as session:
        service(session, artifacts).purge_expired()
        assert session.scalar(select(func.count()).select_from(MailFilingChunk)) == 0
        assert session.scalar(select(func.count()).select_from(MailFiling)) == 0


def test_cancel_and_tool_identity_are_transport_owned(fixture, monkeypatch):
    from contextlib import contextmanager
    import inspect
    import knowledge_index.mail_filing_mcp as transport

    factory, artifacts = fixture
    registered = {}
    class Tools:
        def tool(self, **metadata):
            def register(function):
                registered[function.__name__] = function
                return function
            return register
    @contextmanager
    def audit(*args, **kwargs):
        yield
    calls = []
    def resolve(headers, config):
        calls.append(headers)
        if headers.get("authorization") != "synthetic-authenticated-transport":
            raise PermissionError("unauthenticated")
        return identity("writer")
    monkeypatch.setattr(transport, "resolve_mcp_identity", resolve)
    transport.register_mail_filing_tools(Tools(), factory, lambda: AppConfig(artifact_dir=artifacts.root), audit)
    for tool in registered.values():
        assert not {"principal", "actor_id", "role", "identity"}.intersection(inspect.signature(tool).parameters)
    with pytest.raises(PermissionError):
        registered["list_mail_filing_destinations"](headers={"principal": "writer"})
    headers = {"authorization": "synthetic-authenticated-transport"}
    started = registered["begin_mail_filing"]("m1", "cancel", manifest(), headers=headers)
    assert registered["cancel_mail_filing"](started["id"], headers=headers)["state"] == "cancelled"
    with factory.begin() as session:
        assert session.get(MailFiling, started["id"]) is None
    assert len(calls) == 3


def test_migration_matches_model_and_rolls_back(fixture):
    import importlib.util
    from alembic.migration import MigrationContext
    from alembic.operations import Operations
    from sqlalchemy import inspect
    from pathlib import Path
    factory, _ = fixture
    engine = factory.kw["bind"]
    path = Path(__file__).parents[1] / "migrations/versions/b148f11e0001_authorized_mail_filing.py"
    spec = importlib.util.spec_from_file_location("mail_filing_migration", path)
    migration = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(migration)
    with engine.begin() as connection:
        migration.op = Operations(MigrationContext.configure(connection))
        migration.downgrade()
        assert "mail_filings" not in inspect(connection).get_table_names()
        migration.upgrade()
        for table in (MailFiling.__table__, MailFilingChunk.__table__):
            columns = inspect(connection).get_columns(table.name)
            assert {column["name"] for column in columns} == set(table.columns.keys())
            assert {tuple(fk["constrained_columns"]) for fk in inspect(connection).get_foreign_keys(table.name)} == {tuple(element.parent.name for element in constraint.elements) for constraint in table.foreign_key_constraints}


def test_directory_publication_failure_never_commits_receipt(fixture, monkeypatch):
    import knowledge_index.mail_filing as module
    factory, artifacts = fixture
    with factory.begin() as session:
        started = service(session, artifacts).begin("m1", "durability", manifest())
    for part, data in enumerate((RAW, ATTACHMENT)):
        with factory.begin() as session:
            service(session, artifacts).chunk(started["id"], part, 0, base64.b64encode(data).decode())
    original = module._sync_blob_publication
    def fail(path):
        raise OSError("synthetic directory fsync failure")
    monkeypatch.setattr(module, "_sync_blob_publication", fail)
    with pytest.raises(OSError), factory.begin() as session:
        service(session, artifacts).commit(started["id"])
    with factory.begin() as session:
        assert session.get(MailFiling, started["id"]).state == "uploading"
        assert session.scalar(select(func.count()).select_from(Document)) == 0
        assert session.scalar(select(func.count()).select_from(MailFilingChunk)) == 2
    monkeypatch.setattr(module, "_sync_blob_publication", original)
    with factory.begin() as session:
        assert service(session, artifacts).commit(started["id"])["state"] == "committed"


def test_destinations_page_authorized_rows_before_offset(fixture):
    factory, artifacts = fixture
    with factory.begin() as session:
        for index in range(105):
            session.add(Matter(id=f"later-{index:03}", project_id="p1", title="Later"))
        session.add(ProjectGrant(project_id="p2", principal="user:writer", effect="deny", role="viewer"))
    found = []
    offset = 0
    while offset is not None:
        with factory.begin() as session:
            page = service(session, artifacts).destinations(offset=offset, limit=17)
        found.extend(item["id"] for item in page["results"])
        offset = page["next_offset"]
    assert len(found) == 106
    assert len(set(found)) == 106
    assert "m2" not in found
