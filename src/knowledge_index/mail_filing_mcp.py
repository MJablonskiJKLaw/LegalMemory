"""Narrow filing tools: identity comes from the authenticated MCP transport only."""
from fastmcp.dependencies import CurrentHeaders
from knowledge_index.artifacts import LocalArtifactStore
from knowledge_index.mail_filing import MailFilingService
from knowledge_index.mcp_auth import resolve_mcp_identity


def register_mail_filing_tools(mcp, session_factory, config_provider, audited_call):
    def call(action, headers, operation):
        config = config_provider()
        with audited_call(session_factory, action, headers, config_provider=config_provider):
            identity = resolve_mcp_identity(headers, config)
            with session_factory.begin() as session:
                service = MailFilingService(session, LocalArtifactStore(config.artifact_dir), identity)
                return operation(service)

    @mcp.tool(tags={"read", "filing"}, description="List explicitly writable matter filing destinations. Read access alone does not permit filing.")
    def list_mail_filing_destinations(offset: int = 0, limit: int = 50, headers: dict[str, str] = CurrentHeaders()) -> dict:
        return call("mail_filing.destinations", headers, lambda service: service.destinations(offset=offset, limit=limit))

    @mcp.tool(tags={"write", "filing"}, description="Begin a deliberate authorized matter filing of an original email and attachments. Manifest provenance never grants access.")
    def begin_mail_filing(matter_id: str, replay_key: str, manifest: dict, headers: dict[str, str] = CurrentHeaders()) -> dict:
        return call("mail_filing.begin", headers, lambda service: service.begin(matter_id, replay_key, manifest))

    @mcp.tool(tags={"write", "filing"}, description="Upload one bounded idempotent chunk to the authenticated caller's matter filing.")
    def upload_mail_filing_chunk(filing_id: str, part: int, offset: int, data: str, headers: dict[str, str] = CurrentHeaders()) -> dict:
        return call("mail_filing.chunk", headers, lambda service: service.chunk(filing_id, part, offset, data))

    @mcp.tool(tags={"write", "filing"}, description="Verify original and attachment hashes and atomically commit the authorized matter association and ingestion intent.")
    def commit_mail_filing(filing_id: str, headers: dict[str, str] = CurrentHeaders()) -> dict:
        return call("mail_filing.commit", headers, lambda service: service.commit(filing_id))

    @mcp.tool(tags={"write", "filing"}, description="Cancel an uncommitted upload under current filing authorization. Does not delete filed originals.")
    def cancel_mail_filing(filing_id: str, headers: dict[str, str] = CurrentHeaders()) -> dict:
        return call("mail_filing.cancel", headers, lambda service: service.cancel(filing_id))

    @mcp.tool(tags={"read", "filing"}, description="Read an immutable filing receipt under current document read authorization, independently of write permission.")
    def read_mail_filing(filing_id: str, headers: dict[str, str] = CurrentHeaders()) -> dict:
        return call("mail_filing.read", headers, lambda service: service.read(filing_id))

    @mcp.tool(tags={"read", "filing"}, description="Return only currently readable actual filing association identifiers from up to 200 candidate IDs. Unknown and unauthorized receipts are indistinguishable.")
    def authorized_mail_filings(filing_ids: list[str], headers: dict[str, str] = CurrentHeaders()) -> dict:
        return call("mail_filing.authorized", headers, lambda service: service.authorized(filing_ids))
