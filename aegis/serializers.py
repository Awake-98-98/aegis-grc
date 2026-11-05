"""Stable JSON representations shared by the API and the templates.

Serializers accept ORM objects and return plain dictionaries. Templates get the
same field names as API clients, which keeps the two surfaces honest: adding a
field in one place without the other is visible immediately.
"""

from __future__ import annotations

import json

from aegis.models import AuditEvent, Client, Engagement, Session, Stakeholder, User
from aegis.util.time import as_date_iso, as_iso


def user_public(user: User) -> dict:
    return {
        "id": user.id,
        "email": user.email,
        "display_name": user.display_name,
        "role": user.role,
        "is_active": bool(user.is_active),
        "created_at": as_iso(user.created_at),
        "updated_at": as_iso(user.updated_at),
        "last_login_at": as_iso(user.last_login_at),
    }


def session_public(row: Session) -> dict:
    return {
        "id": row.id,
        "ip": row.ip,
        "user_agent": row.user_agent,
        "created_at": as_iso(row.created_at),
        "expires_at": as_iso(row.expires_at),
    }


def client_public(client: Client, *, engagement_count: int | None = None) -> dict:
    payload = {
        "id": client.id,
        "code": client.code,
        "name": client.name,
        "industry": client.industry,
        "contact_name": client.contact_name,
        "contact_email": client.contact_email,
        "contact_phone": client.contact_phone,
        "status": client.status,
        "notes": client.notes,
        "created_by": client.created_by,
        "created_at": as_iso(client.created_at),
        "updated_at": as_iso(client.updated_at),
    }
    if engagement_count is not None:
        payload["engagement_count"] = engagement_count
    return payload


def engagement_public(engagement: Engagement, *, client: Client | None = None) -> dict:
    client = client or engagement.client
    return {
        "id": engagement.id,
        "code": engagement.code,
        "client_id": engagement.client_id,
        "client_name": client.name if client else "",
        "client_code": client.code if client else "",
        "name": engagement.name,
        "engagement_type": engagement.engagement_type,
        "status": engagement.status,
        "start_date": as_date_iso(engagement.start_date),
        "end_date": as_date_iso(engagement.end_date),
        "lead_user_id": engagement.lead_user_id,
        "scope_summary": engagement.scope_summary,
        "objectives": engagement.objectives,
        "created_by": engagement.created_by,
        "created_at": as_iso(engagement.created_at),
        "updated_at": as_iso(engagement.updated_at),
    }


def stakeholder_public(row: Stakeholder) -> dict:
    return {
        "id": row.id,
        "engagement_id": row.engagement_id,
        "name": row.name,
        "role_title": row.role_title,
        "organization": row.organization,
        "email": row.email,
        "influence": row.influence,
        "interest": row.interest,
        "notes": row.notes,
        "created_at": as_iso(row.created_at),
        "updated_at": as_iso(row.updated_at),
    }


def audit_public(event: AuditEvent) -> dict:
    try:
        detail = json.loads(event.detail_json or "{}")
    except json.JSONDecodeError:
        detail = {"raw": event.detail_json}
    return {
        "id": event.id,
        "actor_user_id": event.actor_user_id,
        "actor_email": event.actor_email,
        "action": event.action,
        "entity_type": event.entity_type,
        "entity_id": event.entity_id,
        "summary": event.summary,
        "detail": detail,
        "ip": event.ip,
        "user_agent": event.user_agent,
        "created_at": as_iso(event.created_at),
    }
