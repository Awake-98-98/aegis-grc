"""Stable JSON representations shared by the API and the templates.

Serializers accept ORM objects and return plain dictionaries. Templates get the
same field names as API clients, which keeps the two surfaces honest: adding a
field in one place without the other is visible immediately.
"""

from __future__ import annotations

import json

from aegis.models import (
    Asset,
    AssetThreat,
    AuditEvent,
    Client,
    Control,
    ControlFramework,
    Engagement,
    RiskAppetite,
    RiskAssessment,
    RiskControlLink,
    RiskItem,
    Session,
    SoAEntry,
    Stakeholder,
    Threat,
    User,
)
from aegis.risk.matrix import DEFAULT_APPETITE
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


def asset_public(asset: Asset, *, threat_count: int | None = None) -> dict:
    payload = {
        "id": asset.id,
        "engagement_id": asset.engagement_id,
        "code": asset.code,
        "name": asset.name,
        "asset_type": asset.asset_type,
        "category": asset.category,
        "owner": asset.owner,
        "department": asset.department,
        "location": asset.location,
        "description": asset.description,
        "confidentiality": asset.confidentiality,
        "integrity": asset.integrity,
        "availability": asset.availability,
        "criticality": asset.criticality,
        "priority_score": asset.priority_score,
        "lifecycle_status": asset.lifecycle_status,
        "created_by": asset.created_by,
        "created_at": as_iso(asset.created_at),
        "updated_at": as_iso(asset.updated_at),
    }
    if threat_count is not None:
        payload["threat_count"] = threat_count
    return payload


def threat_public(threat: Threat, *, asset_count: int | None = None) -> dict:
    payload = {
        "id": threat.id,
        "engagement_id": threat.engagement_id,
        "code": threat.code,
        "name": threat.name,
        "category": threat.category,
        "actor": threat.actor,
        "description": threat.description,
        "created_by": threat.created_by,
        "created_at": as_iso(threat.created_at),
        "updated_at": as_iso(threat.updated_at),
    }
    if asset_count is not None:
        payload["asset_count"] = asset_count
    return payload


def asset_threat_public(
    link: AssetThreat, *, asset: Asset | None = None, threat: Threat | None = None
) -> dict:
    asset = asset or link.asset
    threat = threat or link.threat
    return {
        "id": link.id,
        "asset_id": link.asset_id,
        "threat_id": link.threat_id,
        "asset_code": asset.code if asset else "",
        "asset_name": asset.name if asset else "",
        "threat_code": threat.code if threat else "",
        "threat_name": threat.name if threat else "",
        "vulnerability": link.vulnerability,
        "exposure": link.exposure,
        "notes": link.notes,
        "created_at": as_iso(link.created_at),
        "updated_at": as_iso(link.updated_at),
    }


def risk_assessment_public(
    row: RiskAssessment, *, item_count: int | None = None, summary: dict | None = None
) -> dict:
    payload = {
        "id": row.id,
        "engagement_id": row.engagement_id,
        "code": row.code,
        "title": row.title,
        "status": row.status,
        "assessor": row.assessor,
        "summary": row.summary,
        "issued_at": as_iso(row.issued_at),
        "issued_by": row.issued_by,
        "created_by": row.created_by,
        "created_at": as_iso(row.created_at),
        "updated_at": as_iso(row.updated_at),
    }
    if item_count is not None:
        payload["item_count"] = item_count
    if summary is not None:
        payload["stats"] = summary
    return payload


def risk_item_public(
    item: RiskItem, *, appetite_threshold: int | None = None
) -> dict:
    payload = {
        "id": item.id,
        "assessment_id": item.assessment_id,
        "asset_id": item.asset_id,
        "threat_id": item.threat_id,
        "asset_threat_id": item.asset_threat_id,
        "asset_code": item.asset_code,
        "asset_name": item.asset_name,
        "threat_code": item.threat_code,
        "threat_name": item.threat_name,
        "likelihood": item.likelihood,
        "impact": item.impact,
        "residual_likelihood": item.residual_likelihood,
        "residual_impact": item.residual_impact,
        "inherent_score": item.inherent_score,
        "residual_score": item.residual_score,
        "inherent_severity": item.inherent_severity,
        "residual_severity": item.residual_severity,
        "reduction": item.reduction,
        "treatment": item.treatment,
        "rationale": item.rationale,
        "created_by": item.created_by,
        "created_at": as_iso(item.created_at),
        "updated_at": as_iso(item.updated_at),
    }
    if appetite_threshold is not None:
        payload["within_appetite"] = item.residual_score <= appetite_threshold
    return payload


def risk_appetite_public(row: RiskAppetite | None) -> dict:
    if row is None:
        return {
            "max_acceptable_score": DEFAULT_APPETITE,
            "statement": "",
            "updated_by": None,
            "updated_at": None,
            "is_default": True,
        }
    return {
        "max_acceptable_score": row.max_acceptable_score,
        "statement": row.statement,
        "updated_by": row.updated_by,
        "updated_at": as_iso(row.updated_at),
        "is_default": False,
    }


def control_framework_public(
    row: ControlFramework, *, control_count: int | None = None
) -> dict:
    payload = {
        "id": row.id,
        "code": row.code,
        "name": row.name,
        "version": row.version,
        "publisher": row.publisher,
        "kind": row.kind,
        "description": row.description,
        "created_at": as_iso(row.created_at),
        "updated_at": as_iso(row.updated_at),
    }
    if control_count is not None:
        payload["control_count"] = control_count
    return payload


def control_public(control: Control, *, framework_code: str | None = None) -> dict:
    if framework_code is None and control.framework is not None:
        framework_code = control.framework.code
    return {
        "id": control.id,
        "framework_id": control.framework_id,
        "framework_code": framework_code or "",
        "code": control.code,
        "title": control.title,
        "title_en": control.title_en,
        "domain": control.domain,
        "domain_label": control.domain_label,
        "guidance": control.guidance,
        "sort_order": control.sort_order,
    }


def soa_entry_public(entry: SoAEntry, *, control: Control | None = None) -> dict:
    control = control or entry.control
    return {
        "id": entry.id,
        "engagement_id": entry.engagement_id,
        "control_id": entry.control_id,
        "applicable": bool(entry.applicable),
        "implementation_status": entry.implementation_status,
        "justification": entry.justification,
        "owner": entry.owner,
        "notes": entry.notes,
        "updated_by": entry.updated_by,
        "updated_at": as_iso(entry.updated_at),
        "control": control_public(control) if control else None,
    }


def risk_control_link_public(link: RiskControlLink) -> dict:
    control = link.control
    return {
        "id": link.id,
        "risk_item_id": link.risk_item_id,
        "control_id": link.control_id,
        "coverage": link.coverage,
        "notes": link.notes,
        "created_by": link.created_by,
        "created_at": as_iso(link.created_at),
        "updated_at": as_iso(link.updated_at),
        "control": control_public(control) if control else None,
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
