"""Client ledger service."""

from __future__ import annotations

from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from aegis.errors import Conflict, NotFound
from aegis.models import Client, Engagement
from aegis.security.validation import (
    CLIENT_STATUSES,
    choice,
    optional_email,
    page_params,
    require_text,
)
from aegis.services.audit import AuditService
from aegis.services.auth import AuthContext
from aegis.services.base import ServiceBase
from aegis.util.time import utcnow

MAX_NOTES = 4000


class ClientService(ServiceBase):
    def __init__(self, db: Session) -> None:
        super().__init__(db)

    # ------------------------------------------------------------------- create
    def create(
        self,
        ctx: AuthContext,
        *,
        name: str,
        code: str | None = None,
        industry: str = "",
        contact_name: str = "",
        contact_email: str = "",
        contact_phone: str = "",
        status: str = "prospect",
        notes: str = "",
        ip: str = "",
        user_agent: str = "",
    ) -> Client:
        self.require(ctx, "client:write")
        clean_name = require_text(name, "name", max_length=200)
        clean_status = choice(status, CLIENT_STATUSES, "status", default="prospect")
        final_code = require_text(code, "code", max_length=32) if code else self._next_code()
        if self.db.execute(select(Client).where(Client.code == final_code)).scalar_one_or_none():
            raise Conflict(f"client code already exists: {final_code}")

        client = Client(
            code=final_code,
            name=clean_name,
            industry=require_text(industry, "industry", max_length=120, allow_empty=True),
            contact_name=require_text(
                contact_name, "contact_name", max_length=120, allow_empty=True
            ),
            contact_email=optional_email(contact_email, "contact_email"),
            contact_phone=require_text(
                contact_phone, "contact_phone", max_length=64, allow_empty=True
            ),
            status=clean_status,
            notes=require_text(notes, "notes", max_length=MAX_NOTES, allow_empty=True),
            created_by=ctx.user.id,
        )
        self.db.add(client)
        self.db.flush()
        self.audit.record(
            action="client.create",
            entity_type="client",
            entity_id=client.id,
            summary=f"新建客户 {client.code} {client.name}",
            detail={"code": client.code, "name": client.name, "status": client.status},
            actor=self.actor(ctx, ip, user_agent),
        )
        self.db.commit()
        return client

    # ------------------------------------------------------------------- update
    def update(
        self,
        ctx: AuthContext,
        client_id: str,
        *,
        name: str | None = None,
        industry: str | None = None,
        contact_name: str | None = None,
        contact_email: str | None = None,
        contact_phone: str | None = None,
        status: str | None = None,
        notes: str | None = None,
        ip: str = "",
        user_agent: str = "",
    ) -> Client:
        self.require(ctx, "client:write")
        client = self.get(client_id)
        before = _client_snapshot(client)

        if name is not None:
            client.name = require_text(name, "name", max_length=200)
        if industry is not None:
            client.industry = require_text(
                industry, "industry", max_length=120, allow_empty=True
            )
        if contact_name is not None:
            client.contact_name = require_text(
                contact_name, "contact_name", max_length=120, allow_empty=True
            )
        if contact_email is not None:
            client.contact_email = optional_email(contact_email, "contact_email")
        if contact_phone is not None:
            client.contact_phone = require_text(
                contact_phone, "contact_phone", max_length=64, allow_empty=True
            )
        if status is not None:
            client.status = choice(status, CLIENT_STATUSES, "status")
        if notes is not None:
            client.notes = require_text(notes, "notes", max_length=MAX_NOTES, allow_empty=True)
        client.updated_at = utcnow()

        after = _client_snapshot(client)
        self.audit.record(
            action="client.update",
            entity_type="client",
            entity_id=client.id,
            summary=f"更新客户 {client.code} {client.name}",
            detail={"before": before, "after": after},
            actor=self.actor(ctx, ip, user_agent),
        )
        self.db.commit()
        return client

    # --------------------------------------------------------------------- read
    def get(self, client_id: str) -> Client:
        client = self.db.get(Client, client_id)
        if client is None:
            raise NotFound("client not found")
        return client

    def get_for(self, ctx: AuthContext, client_id: str) -> Client:
        self.require(ctx, "client:read")
        return self.get(client_id)

    def list(
        self,
        ctx: AuthContext,
        *,
        q: str = "",
        status: str = "",
        page: int = 1,
        page_size: int = 20,
    ) -> tuple[list[Client], int, int, int]:
        self.require(ctx, "client:read")
        page, page_size = page_params(page, page_size)
        conditions = []
        if q.strip():
            needle = f"%{q.strip()}%"
            conditions.append(
                or_(
                    Client.name.ilike(needle),
                    Client.code.ilike(needle),
                    Client.industry.ilike(needle),
                    Client.contact_name.ilike(needle),
                )
            )
        if status:
            if status not in CLIENT_STATUSES:
                raise Conflict(f"unknown client status: {status}")
            conditions.append(Client.status == status)

        base = select(Client)
        count_stmt = select(func.count(Client.id))
        if conditions:
            base = base.where(*conditions)
            count_stmt = count_stmt.where(*conditions)
        total = int(self.db.execute(count_stmt).scalar() or 0)
        rows = list(
            self.db.execute(
                base.order_by(Client.updated_at.desc()).limit(page_size).offset((page - 1) * page_size)
            ).scalars()
        )
        return rows, total, page, page_size

    def engagement_counts(self, client_ids: list[str]) -> dict[str, int]:
        if not client_ids:
            return {}
        rows = self.db.execute(
            select(Engagement.client_id, func.count(Engagement.id))
            .where(Engagement.client_id.in_(client_ids))
            .group_by(Engagement.client_id)
        ).all()
        return {client_id: int(count) for client_id, count in rows}

    def _next_code(self) -> str:
        total = int(self.db.execute(select(func.count(Client.id)).select_from(Client)).scalar() or 0)
        candidate = total + 1
        while True:
            code = f"CL-{candidate:04d}"
            exists = self.db.execute(select(Client.id).where(Client.code == code)).scalar_one_or_none()
            if exists is None:
                return code
            candidate += 1

    @staticmethod
    def audit_service(db: Session) -> AuditService:
        return AuditService(db)


def _client_snapshot(client: Client) -> dict:
    return {
        "name": client.name,
        "industry": client.industry,
        "contact_name": client.contact_name,
        "contact_email": client.contact_email,
        "contact_phone": client.contact_phone,
        "status": client.status,
        "notes": client.notes,
    }
