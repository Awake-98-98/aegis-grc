"""Command line entry point.

``python -m aegis <command>`` is the only operational surface an operator
needs: initialise the database, create the first administrator, run the
server, inspect status, and load a fictional demo dataset for screenshots.
"""

from __future__ import annotations

import argparse
import getpass
import sys
from pathlib import Path

from sqlalchemy import func, select

from aegis import __app_name__, __version__
from aegis.config import ConfigError, Settings
from aegis.db import create_db_engine, create_session_factory, run_migrations, schema_status
from aegis.errors import AppError, NotFound
from aegis.models import Client, Engagement, Session as LoginSession, Stakeholder, User
from aegis.security.passwords import hash_password
from aegis.services.auth import AuthContext, AuthService
from aegis.services.clients import ClientService
from aegis.services.engagements import EngagementService
from aegis.services.stakeholders import StakeholderService
from aegis.util.time import utcnow


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="aegis", description=f"{__app_name__} {__version__}")
    parser.add_argument("--home", default=None, help="data directory (default: AEGIS_HOME or ./aegis-data)")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("init", help="create the database and apply migrations")

    admin = sub.add_parser("create-admin", help="create the first administrator")
    admin.add_argument("--email", default=None)
    admin.add_argument("--display-name", default=None)
    admin.add_argument("--password", default=None, help="prefer AEGIS_ADMIN_PASSWORD or the interactive prompt")

    user = sub.add_parser("create-user", help="create a member (requires an existing administrator)")
    user.add_argument("--email", required=True)
    user.add_argument("--display-name", required=True)
    user.add_argument("--password", default=None)
    user.add_argument("--role", default="consultant", choices=["admin", "consultant", "viewer"])

    serve = sub.add_parser("serve", help="run the web console")
    serve.add_argument("--host", default=None)
    serve.add_argument("--port", type=int, default=None)
    serve.add_argument("--reload", action="store_true", help="development only")

    sub.add_parser("status", help="show schema, counts and database location")
    sub.add_parser("seed-demo", help="load fictional demo clients and engagements")
    sub.add_parser("prune-sessions", help="delete expired and revoked sessions")
    return parser


def _settings(args) -> Settings:
    return Settings.load(home=args.home)


def _open(settings: Settings):
    engine = create_db_engine(settings)
    run_migrations(engine)
    return engine, create_session_factory(engine)


def _cli_ctx(user: User) -> AuthContext:
    now = utcnow()
    transient = LoginSession(
        id="cli",
        user_id=user.id,
        token_hash="",
        csrf_token="",
        created_at=now,
        expires_at=now,
        last_seen_at=now,
        ip="cli",
        user_agent="cli",
    )
    return AuthContext(user=user, session=transient, via="cli")


def _prompt_password(env_name: str = "AEGIS_ADMIN_PASSWORD") -> str:
    import os

    value = os.environ.get(env_name)
    if value:
        return value
    return getpass.getpass("Password (10+ chars, letters and digits): ")


def cmd_init(settings: Settings) -> int:
    engine = create_db_engine(settings)
    applied = run_migrations(engine)
    status = schema_status(engine)
    print(f"database: {settings.database_url}")
    print(f"schema:   {status['current']}/{status['latest']}")
    if applied:
        for migration in applied:
            print(f"applied:  v{migration.version} {migration.name}")
    else:
        print("applied:  none (already current)")
    return 0


def cmd_create_admin(args, settings: Settings) -> int:
    from aegis.security.passwords import validate_password

    email = args.email or input("Email: ")
    display_name = args.display_name or input("Display name: ")
    password = args.password or _prompt_password()
    validate_password(password)
    engine, factory = _open(settings)
    with factory() as db:
        service = AuthService(db, settings)
        user, _ = service.bootstrap(
            email=email,
            display_name=display_name,
            password=password,
            ip="cli",
            user_agent="aegis-cli",
        )
        print(f"created administrator: {user.email} ({user.id})")
    engine.dispose()
    return 0


def cmd_create_user(args, settings: Settings) -> int:
    from aegis.security.passwords import validate_password

    password = args.password or _prompt_password("AEGIS_USER_PASSWORD")
    validate_password(password)
    engine, factory = _open(settings)
    with factory() as db:
        admin = db.execute(
            select(User).where(User.role == "admin", User.is_active.is_(True)).limit(1)
        ).scalar_one_or_none()
        if admin is None:
            print("error: no active administrator found; run create-admin first", file=sys.stderr)
            return 2
        user = AuthService(db, settings).create_user(
            _cli_ctx(admin),
            email=args.email,
            display_name=args.display_name,
            password=password,
            role=args.role,
            ip="cli",
            user_agent="aegis-cli",
        )
        print(f"created user: {user.email} ({user.role})")
    engine.dispose()
    return 0


def cmd_serve(args, settings: Settings) -> int:
    import uvicorn

    from aegis.app import create_app

    host = args.host or settings.host
    port = args.port or settings.port
    app = create_app(settings)
    print(f"{__app_name__} {__version__} listening on http://{host}:{port}")
    uvicorn.run(app, host=host, port=port, log_level="info")
    return 0


def cmd_status(settings: Settings) -> int:
    engine, factory = _open(settings)
    with factory() as db:
        counts = {
            "users": int(db.execute(select(func.count(User.id)).select_from(User)).scalar() or 0),
            "clients": int(db.execute(select(func.count(Client.id)).select_from(Client)).scalar() or 0),
            "engagements": int(
                db.execute(select(func.count(Engagement.id)).select_from(Engagement)).scalar() or 0
            ),
            "stakeholders": int(
                db.execute(select(func.count(Stakeholder.id)).select_from(Stakeholder)).scalar() or 0
            ),
        }
        status = schema_status(engine)
    engine.dispose()
    print(f"{__app_name__} {__version__}  env={settings.environment}")
    print(f"data home: {settings.home}")
    print(f"database:  {settings.database_url}")
    print(f"schema:    {status['current']}/{status['latest']}")
    for key, value in counts.items():
        print(f"{key + ':':<12}{value}")
    return 0


def cmd_seed_demo(args, settings: Settings) -> int:
    """Load a fictional dataset. Safe to run once; refuses to duplicate it."""
    engine, factory = _open(settings)
    demo_email = "consultant@aegis.local"
    demo_password = "DemoPass12345"
    with factory() as db:
        admin = db.execute(
            select(User).where(User.role == "admin", User.is_active.is_(True)).limit(1)
        ).scalar_one_or_none()
        created_admin = False
        if admin is None:
            admin, _ = AuthService(db, settings).bootstrap(
                email=demo_email,
                display_name="演示顾问",
                password=demo_password,
                ip="cli",
                user_agent="aegis-cli",
            )
            created_admin = True
        existing = db.execute(select(Client).where(Client.code == "CL-0001")).scalar_one_or_none()
        if existing is not None:
            print("demo data already present; nothing to do")
            engine.dispose()
            return 0
        ctx = _cli_ctx(admin)
        clients = ClientService(db)
        engagements = EngagementService(db)
        stakeholders = StakeholderService(db)

        north = clients.create(
            ctx,
            code="CL-0001",
            name="北辰智造集团",
            industry="高端制造",
            contact_name="周敏",
            contact_email="zhou.min@beichen.example",
            contact_phone="021-6000-1000",
            status="active",
            notes="年度信息安全风险评估框架客户。",
        )
        bank = clients.create(
            ctx,
            code="CL-0002",
            name="澜江农商银行",
            industry="金融",
            contact_name="李承泽",
            contact_email="li.chengze@lanjiang.example",
            status="prospect",
            notes="正在洽谈等保 2.0 三级测评陪跑。",
        )
        clinic = clients.create(
            ctx,
            code="CL-0003",
            name="和宁医疗科技",
            industry="医疗健康",
            contact_name="陈曦",
            contact_email="chen.xi@hening.example",
            status="active",
        )

        e1 = engagements.create(
            ctx,
            client_id=north.id,
            code="ENG-2026-0001",
            name="北辰集团 2026 年度安全风险评估",
            engagement_type="risk_assessment",
            start_date="2026-10-08",
            end_date="2026-12-18",
            lead_user_id=admin.id,
            scope_summary="总部园区、两个生产基地与混合云环境；覆盖核心 MES、ERP 与办公网。",
            objectives="识别关键业务资产面临的 top 风险，形成整改优先级与年度预算建议。",
        )
        engagements.transition(ctx, e1.id, "scoping", note="完成入场会与范围确认")
        engagements.transition(ctx, e1.id, "fieldwork", note="开始资产访谈与样本抽查")

        e2 = engagements.create(
            ctx,
            client_id=bank.id,
            code="ENG-2026-0002",
            name="澜江农商银行等保三级差距分析",
            engagement_type="compliance_audit",
            start_date="2026-11-02",
            end_date="2027-01-15",
            lead_user_id=admin.id,
            scope_summary="核心业务系统、网上银行与灾备中心。",
            objectives="对照等保 2.0 三级要求识别差距，输出整改清单与复测计划。",
        )
        engagements.transition(ctx, e2.id, "scoping", note="资料预审完成")

        e3 = engagements.create(
            ctx,
            client_id=clinic.id,
            code="ENG-2026-0003",
            name="和宁医疗数据出境合规咨询",
            engagement_type="security_planning",
            start_date="2026-11-10",
            end_date="2026-12-31",
            scope_summary="互联网医院平台与跨境科研协作数据流。",
            objectives="梳理数据出境场景，形成申报路径与整改路线图。",
        )

        stakeholder_rows = [
            (e1.id, "周敏", "集团 CIO", "北辰智造集团", "ci o@beichen.example", "high", "high"),
            (e1.id, "王海", "信息安全经理", "北辰智造集团", "wang.hai@beichen.example", "medium", "high"),
            (e2.id, "李承泽", "科技部总经理", "澜江农商银行", "li.chengze@lanjiang.example", "high", "high"),
        ]
        for engagement_id, name, role_title, organization, email, influence, interest in stakeholder_rows:
            stakeholders.create(
                ctx,
                engagement_id,
                name=name,
                role_title=role_title,
                organization=organization,
                email=email.replace(" ", ""),
                influence=influence,
                interest=interest,
            )

        print("demo data loaded:")
        print(f"  clients:     {north.code}, {bank.code}, {clinic.code}")
        print(f"  engagements: {e1.code}, {e2.code}, {e3.code}")
        if created_admin:
            print(f"  demo admin:  {demo_email} / {demo_password}")
    engine.dispose()
    return 0


def cmd_prune_sessions(args, settings: Settings) -> int:
    engine, factory = _open(settings)
    with factory() as db:
        removed = AuthService(db, settings).cleanup_expired()
    engine.dispose()
    print(f"removed {removed} expired or revoked sessions")
    return 0


COMMANDS = {
    "init": cmd_init,
    "create-admin": cmd_create_admin,
    "create-user": cmd_create_user,
    "serve": cmd_serve,
    "status": cmd_status,
    "seed-demo": cmd_seed_demo,
    "prune-sessions": cmd_prune_sessions,
}


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    try:
        settings = _settings(args)
        command = COMMANDS[args.command]
        if args.command in {"init", "status"}:
            return command(settings)
        return command(args, settings)
    except (ConfigError, AppError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
