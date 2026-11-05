"""Authentication, session lifecycle and user administration."""

from __future__ import annotations

import time
from dataclasses import dataclass
from datetime import timedelta
from typing import Iterable

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from aegis.config import Settings
from aegis.errors import (
    AccountInactive,
    Conflict,
    Forbidden,
    NotFound,
    RateLimited,
    Unauthorized,
    ValidationFailure,
)
from aegis.models import Session as LoginSession
from aegis.models import User
from aegis.security.passwords import hash_password, validate_password, verify_password
from aegis.security.rbac import is_known_role
from aegis.security.tokens import new_csrf_token, new_token, token_digest
from aegis.security.validation import normalize_email, require_text
from aegis.services.audit import Actor, AuditService, actor_from_user
from aegis.util.time import utcnow


@dataclass(frozen=True, slots=True)
class AuthContext:
    user: User
    session: LoginSession
    via: str

    @property
    def role(self) -> str:
        return self.user.role


@dataclass(frozen=True, slots=True)
class LoginResult:
    user: User
    token: str
    csrf_token: str
    session_id: str
    expires_at: object


class LoginRateLimiter:
    """In-process sliding window.

    A single-process deployment is the supported shape today; the limitation is
    written down in the design record rather than hidden. Attempts are keyed by
    email + client IP so one noisy source cannot lock every account.
    """

    def __init__(self) -> None:
        self._events: dict[str, list[float]] = {}

    def _prune(self, key: str, window_seconds: int) -> None:
        cutoff = time.monotonic() - window_seconds
        kept = [stamp for stamp in self._events.get(key, []) if stamp >= cutoff]
        if kept:
            self._events[key] = kept
        else:
            self._events.pop(key, None)

    def blocked(self, key: str, max_attempts: int, window_seconds: int) -> bool:
        self._prune(key, window_seconds)
        return len(self._events.get(key, [])) >= max_attempts

    def add_failure(self, key: str, window_seconds: int) -> None:
        self._prune(key, window_seconds)
        self._events.setdefault(key, []).append(time.monotonic())

    def clear(self, key: str) -> None:
        self._events.pop(key, None)

    def reset(self) -> None:
        self._events.clear()


LOGIN_LIMITER = LoginRateLimiter()


class AuthService:
    def __init__(self, db: Session, settings: Settings, limiter: LoginRateLimiter | None = None) -> None:
        self.db = db
        self.settings = settings
        self.audit = AuditService(db)
        self.limiter = limiter or LOGIN_LIMITER

    # ---------------------------------------------------------------- bootstrap
    def has_users(self) -> bool:
        return int(self.db.execute(select(func.count(User.id)).select_from(User)).scalar() or 0) > 0

    def bootstrap(
        self,
        *,
        email: str,
        display_name: str,
        password: str,
        ip: str = "",
        user_agent: str = "",
    ) -> tuple[User, LoginResult]:
        if self.has_users():
            raise Conflict("workspace already has an administrator")
        user = self._create_user_row(
            email=email,
            display_name=display_name,
            password=password,
            role="admin",
            actor=None,
        )
        self.audit.record(
            action="user.bootstrap",
            entity_type="user",
            entity_id=user.id,
            summary=f"创建初始管理员 {user.email}",
            detail={"role": user.role},
            actor=actor_from_user(user, ip, user_agent),
        )
        result = self._issue_session(user, ip, user_agent)
        self.db.commit()
        return user, result

    # -------------------------------------------------------------------- users
    def create_user(
        self,
        actor_ctx: AuthContext,
        *,
        email: str,
        display_name: str,
        password: str,
        role: str,
        ip: str = "",
        user_agent: str = "",
    ) -> User:
        self._require_admin(actor_ctx)
        if not is_known_role(role):
            raise ValidationFailure(f"unknown role: {role}", details={"field": "role"})
        user = self._create_user_row(
            email=email,
            display_name=display_name,
            password=password,
            role=role,
            actor=actor_from_user(actor_ctx.user, ip, user_agent),
        )
        self.audit.record(
            action="user.create",
            entity_type="user",
            entity_id=user.id,
            summary=f"新建用户 {user.email}（{user.role}）",
            detail={"email": user.email, "role": user.role},
            actor=actor_from_user(actor_ctx.user, ip, user_agent),
        )
        self.db.commit()
        return user

    def update_user(
        self,
        actor_ctx: AuthContext,
        user_id: str,
        *,
        display_name: str | None = None,
        role: str | None = None,
        is_active: bool | None = None,
        ip: str = "",
        user_agent: str = "",
    ) -> User:
        self._require_admin(actor_ctx)
        user = self.db.get(User, user_id)
        if user is None:
            raise NotFound("user not found")
        before = {"display_name": user.display_name, "role": user.role, "is_active": user.is_active}

        if role is not None and role != user.role:
            if not is_known_role(role):
                raise ValidationFailure(f"unknown role: {role}", details={"field": "role"})
            if user.role == "admin" and self._active_admin_count(exclude=user.id) == 0:
                raise Conflict("cannot demote the last active administrator")
            user.role = role
        if is_active is not None and is_active != user.is_active:
            if not is_active and user.role == "admin" and self._active_admin_count(exclude=user.id) == 0:
                raise Conflict("cannot deactivate the last active administrator")
            if not is_active:
                self._revoke_all_sessions(user.id)
            user.is_active = is_active
        if display_name is not None:
            user.display_name = require_text(display_name, "display_name", max_length=120)
        user.updated_at = utcnow()

        after = {"display_name": user.display_name, "role": user.role, "is_active": user.is_active}
        self.audit.record(
            action="user.update",
            entity_type="user",
            entity_id=user.id,
            summary=f"更新用户 {user.email}",
            detail={"before": before, "after": after},
            actor=actor_from_user(actor_ctx.user, ip, user_agent),
        )
        self.db.commit()
        return user

    def list_users(self) -> list[User]:
        return list(self.db.execute(select(User).order_by(User.created_at.asc())).scalars())

    # -------------------------------------------------------------------- login
    def login(
        self,
        *,
        email: str,
        password: str,
        ip: str = "",
        user_agent: str = "",
    ) -> LoginResult:
        normalized = (email or "").strip().lower()
        key = f"{normalized}|{ip}"
        if self.limiter.blocked(
            key, self.settings.login_max_attempts, self.settings.login_window_seconds
        ):
            raise RateLimited("too many login attempts; retry later")
        user = self.db.execute(select(User).where(User.email == normalized)).scalar_one_or_none()
        if user is None or not verify_password(user.password_hash, password):
            self.limiter.add_failure(key, self.settings.login_window_seconds)
            self.audit.record(
                action="auth.login_failed",
                entity_type="auth",
                entity_id=user.id if user else "",
                summary=f"登录失败：{(normalized or '空邮箱')[:200]}",
                detail={"reason": "bad_credentials"},
                actor=Actor(user_id=None, email=normalized[:254], ip=ip[:64], user_agent=user_agent[:255]),
            )
            self.db.commit()
            raise Unauthorized("email or password is incorrect")
        if not user.is_active:
            self.audit.record(
                action="auth.login_blocked",
                entity_type="user",
                entity_id=user.id,
                summary=f"停用账号尝试登录：{user.email}",
                actor=actor_from_user(user, ip, user_agent),
            )
            self.db.commit()
            raise AccountInactive("account is inactive")
        self.limiter.clear(key)
        result = self._issue_session(user, ip, user_agent)
        user.last_login_at = utcnow()
        self.audit.record(
            action="auth.login",
            entity_type="user",
            entity_id=user.id,
            summary=f"登录成功：{user.email}",
            actor=actor_from_user(user, ip, user_agent),
        )
        self.db.commit()
        return result

    def logout(self, ctx: AuthContext, ip: str = "", user_agent: str = "") -> None:
        ctx.session.revoked_at = utcnow()
        self.audit.record(
            action="auth.logout",
            entity_type="user",
            entity_id=ctx.user.id,
            summary=f"退出登录：{ctx.user.email}",
            actor=actor_from_user(ctx.user, ip, user_agent),
        )
        self.db.commit()

    def change_password(
        self,
        ctx: AuthContext,
        *,
        current_password: str,
        new_password: str,
        ip: str = "",
        user_agent: str = "",
    ) -> None:
        if not verify_password(ctx.user.password_hash, current_password):
            raise ValidationFailure("current password is incorrect")
        validate_password(new_password)
        if verify_password(ctx.user.password_hash, new_password):
            raise ValidationFailure("new password must differ from the current one")
        ctx.user.password_hash = hash_password(new_password)
        ctx.user.updated_at = utcnow()
        # Keep the current session, revoke every other one.
        self._revoke_all_sessions(ctx.user.id, except_session_id=ctx.session.id)
        self.audit.record(
            action="user.password_change",
            entity_type="user",
            entity_id=ctx.user.id,
            summary=f"修改密码：{ctx.user.email}",
            actor=actor_from_user(ctx.user, ip, user_agent),
        )
        self.db.commit()

    # ------------------------------------------------------------------ session
    def resolve(self, token: str | None, via: str = "cookie") -> AuthContext | None:
        if not token:
            return None
        row = self.db.execute(
            select(LoginSession).where(LoginSession.token_hash == token_digest(token))
        ).scalar_one_or_none()
        now = utcnow()
        if row is None or row.revoked_at is not None or row.expires_at <= now:
            return None
        user = self.db.get(User, row.user_id)
        if user is None or not user.is_active:
            return None
        return AuthContext(user=user, session=row, via=via)

    def cleanup_expired(self) -> int:
        now = utcnow()
        expired = list(
            self.db.execute(
                select(LoginSession).where(
                    (LoginSession.expires_at <= now) | (LoginSession.revoked_at.is_not(None))
                )
            ).scalars()
        )
        for row in expired:
            self.db.delete(row)
        if expired:
            self.db.commit()
        return len(expired)

    # ------------------------------------------------------------------ private
    def _create_user_row(
        self,
        *,
        email: str,
        display_name: str,
        password: str,
        role: str,
        actor: Actor | None,
    ) -> User:
        normalized = normalize_email(email)
        existing = self.db.execute(select(User).where(User.email == normalized)).scalar_one_or_none()
        if existing is not None:
            raise Conflict(f"email already registered: {normalized}")
        validate_password(password)
        user = User(
            email=normalized,
            display_name=require_text(display_name, "display_name", max_length=120),
            password_hash=hash_password(password),
            role=role,
            is_active=True,
        )
        self.db.add(user)
        self.db.flush()
        return user

    def _issue_session(self, user: User, ip: str, user_agent: str) -> LoginResult:
        token = new_token()
        now = utcnow()
        expires = now + timedelta(hours=self.settings.session_ttl_hours)
        row = LoginSession(
            user_id=user.id,
            token_hash=token_digest(token),
            csrf_token=new_csrf_token(),
            created_at=now,
            expires_at=expires,
            last_seen_at=now,
            ip=(ip or "")[:64],
            user_agent=(user_agent or "")[:255],
        )
        self.db.add(row)
        self.db.flush()
        return LoginResult(
            user=user,
            token=token,
            csrf_token=row.csrf_token,
            session_id=row.id,
            expires_at=expires,
        )

    def _active_admin_count(self, exclude: str | None = None) -> int:
        stmt = select(func.count(User.id)).where(User.role == "admin", User.is_active.is_(True))
        if exclude:
            stmt = stmt.where(User.id != exclude)
        return int(self.db.execute(stmt).scalar() or 0)

    def _revoke_all_sessions(self, user_id: str, except_session_id: str | None = None) -> None:
        rows = self.db.execute(
            select(LoginSession).where(
                LoginSession.user_id == user_id, LoginSession.revoked_at.is_(None)
            )
        ).scalars()
        now = utcnow()
        for row in rows:
            if except_session_id and row.id == except_session_id:
                continue
            row.revoked_at = now

    def _require_admin(self, ctx: AuthContext) -> None:
        if ctx.user.role != "admin":
            raise Forbidden("administrator role required")

    def _require_permissions(self, ctx: AuthContext, permissions: Iterable[str]) -> None:
        from aegis.security.rbac import missing_permissions

        missing = missing_permissions(ctx.user.role, permissions)
        if missing:
            raise Forbidden("missing permission: " + ", ".join(missing))
