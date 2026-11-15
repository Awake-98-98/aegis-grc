"""Request/response schemas for the JSON API.

Pydantic handles shape and type coercion; business rules (status values,
date ordering, password policy, permissions) stay in the service layer so the
web forms and the API share exactly one implementation.
"""

from __future__ import annotations

from datetime import date

from pydantic import BaseModel, Field


class BootstrapRequest(BaseModel):
    email: str = Field(min_length=3, max_length=254)
    display_name: str = Field(min_length=1, max_length=120)
    password: str = Field(min_length=10, max_length=128)


class LoginRequest(BaseModel):
    email: str = Field(min_length=3, max_length=254)
    password: str = Field(min_length=1, max_length=128)


class ChangePasswordRequest(BaseModel):
    current_password: str = Field(min_length=1, max_length=128)
    new_password: str = Field(min_length=10, max_length=128)


class UserCreateRequest(BaseModel):
    email: str = Field(min_length=3, max_length=254)
    display_name: str = Field(min_length=1, max_length=120)
    password: str = Field(min_length=10, max_length=128)
    role: str = "consultant"


class UserUpdateRequest(BaseModel):
    display_name: str | None = Field(default=None, max_length=120)
    role: str | None = None
    is_active: bool | None = None


class ClientCreateRequest(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    code: str | None = Field(default=None, max_length=32)
    industry: str = Field(default="", max_length=120)
    contact_name: str = Field(default="", max_length=120)
    contact_email: str = Field(default="", max_length=254)
    contact_phone: str = Field(default="", max_length=64)
    status: str = "prospect"
    notes: str = Field(default="", max_length=4000)


class ClientUpdateRequest(BaseModel):
    name: str | None = Field(default=None, max_length=200)
    industry: str | None = Field(default=None, max_length=120)
    contact_name: str | None = Field(default=None, max_length=120)
    contact_email: str | None = Field(default=None, max_length=254)
    contact_phone: str | None = Field(default=None, max_length=64)
    status: str | None = None
    notes: str | None = Field(default=None, max_length=4000)


class EngagementCreateRequest(BaseModel):
    client_id: str = Field(min_length=1, max_length=32)
    name: str = Field(min_length=1, max_length=200)
    code: str | None = Field(default=None, max_length=32)
    engagement_type: str = "risk_assessment"
    start_date: date | None = None
    end_date: date | None = None
    lead_user_id: str | None = Field(default=None, max_length=32)
    scope_summary: str = Field(default="", max_length=4000)
    objectives: str = Field(default="", max_length=4000)


class EngagementUpdateRequest(BaseModel):
    name: str | None = Field(default=None, max_length=200)
    engagement_type: str | None = None
    start_date: date | None = None
    end_date: date | None = None
    lead_user_id: str | None = Field(default=None, max_length=32)
    scope_summary: str | None = Field(default=None, max_length=4000)
    objectives: str | None = Field(default=None, max_length=4000)


class TransitionRequest(BaseModel):
    status: str
    note: str = Field(default="", max_length=500)


class StakeholderCreateRequest(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    role_title: str = Field(default="", max_length=120)
    organization: str = Field(default="", max_length=200)
    email: str = Field(default="", max_length=254)
    influence: str = "medium"
    interest: str = "medium"
    notes: str = Field(default="", max_length=2000)


class StakeholderUpdateRequest(BaseModel):
    name: str | None = Field(default=None, max_length=120)
    role_title: str | None = Field(default=None, max_length=120)
    organization: str | None = Field(default=None, max_length=200)
    email: str | None = Field(default=None, max_length=254)
    influence: str | None = None
    interest: str | None = None
    notes: str | None = Field(default=None, max_length=2000)


class AssetCreateRequest(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    code: str | None = Field(default=None, max_length=32)
    asset_type: str = "supporting"
    category: str = "other"
    owner: str = Field(default="", max_length=120)
    department: str = Field(default="", max_length=120)
    location: str = Field(default="", max_length=200)
    description: str = Field(default="", max_length=2000)
    confidentiality: int = 2
    integrity: int = 2
    availability: int = 2
    lifecycle_status: str = "active"


class AssetUpdateRequest(BaseModel):
    name: str | None = Field(default=None, max_length=200)
    asset_type: str | None = None
    category: str | None = None
    owner: str | None = Field(default=None, max_length=120)
    department: str | None = Field(default=None, max_length=120)
    location: str | None = Field(default=None, max_length=200)
    description: str | None = Field(default=None, max_length=2000)
    confidentiality: int | None = None
    integrity: int | None = None
    availability: int | None = None
    lifecycle_status: str | None = None


class ThreatCreateRequest(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    code: str | None = Field(default=None, max_length=32)
    category: str = "other"
    actor: str = "external"
    description: str = Field(default="", max_length=2000)


class ThreatUpdateRequest(BaseModel):
    name: str | None = Field(default=None, max_length=200)
    category: str | None = None
    actor: str | None = None
    description: str | None = Field(default=None, max_length=2000)


class AssetThreatLinkRequest(BaseModel):
    threat_id: str = Field(min_length=1, max_length=32)
    vulnerability: str = Field(default="", max_length=4000)
    exposure: str = "medium"
    notes: str = Field(default="", max_length=4000)


class AssetThreatUpdateRequest(BaseModel):
    vulnerability: str | None = Field(default=None, max_length=4000)
    exposure: str | None = None
    notes: str | None = Field(default=None, max_length=4000)
