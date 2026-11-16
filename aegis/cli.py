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
from aegis.models import (
    Asset,
    AssetThreat,
    Client,
    Engagement,
    RiskAppetite,
    RiskAssessment,
    RiskItem,
    Session as LoginSession,
    Stakeholder,
    Threat,
    User,
)
from aegis.services.asset_import import AssetImportService, csv_template
from aegis.services.assets import AssetService
from aegis.services.auth import AuthContext, AuthService
from aegis.services.clients import ClientService
from aegis.services.engagements import EngagementService
from aegis.services.risks import RiskAssessmentService, RiskService
from aegis.services.stakeholders import StakeholderService
from aegis.services.threats import ThreatService
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

    assets = sub.add_parser("assets", help="asset inventory utilities")
    assets_sub = assets.add_subparsers(dest="assets_command", required=True)
    assets_import = assets_sub.add_parser("import", help="import assets from a CSV file")
    assets_import.add_argument("--engagement", required=True, help="engagement code, e.g. ENG-2026-0001")
    assets_import.add_argument("--file", required=True, type=Path, help="path to the CSV file")
    assets_template = assets_sub.add_parser("template", help="write the CSV template")
    assets_template.add_argument("--out", type=Path, default=None, help="defaults to stdout")
    assets_export = assets_sub.add_parser("export", help="export the asset list as CSV")
    assets_export.add_argument("--engagement", required=True)
    assets_export.add_argument("--out", type=Path, default=None)

    risks = sub.add_parser("risks", help="risk assessment utilities")
    risks_sub = risks.add_subparsers(dest="risks_command", required=True)
    risks_list = risks_sub.add_parser("list", help="list assessment batches of an engagement")
    risks_list.add_argument("--engagement", required=True, help="engagement code")
    risks_export = risks_sub.add_parser("export", help="export one register as CSV")
    risks_export.add_argument("--engagement", required=True)
    risks_export.add_argument("--assessment", required=True, help="assessment code, e.g. RA-0001")
    risks_export.add_argument("--out", type=Path, default=None)
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
            "assets": int(
                db.execute(select(func.count(Asset.id)).select_from(Asset)).scalar() or 0
            ),
            "threats": int(
                db.execute(select(func.count(Threat.id)).select_from(Threat)).scalar() or 0
            ),
            "threat_links": int(
                db.execute(select(func.count(AssetThreat.id)).select_from(AssetThreat)).scalar() or 0
            ),
            "assessments": int(
                db.execute(select(func.count(RiskAssessment.id)).select_from(RiskAssessment)).scalar()
                or 0
            ),
            "risk_items": int(
                db.execute(select(func.count(RiskItem.id)).select_from(RiskItem)).scalar() or 0
            ),
            "risk_appetite": int(
                db.execute(select(func.count(RiskAppetite.id)).select_from(RiskAppetite)).scalar()
                or 0
            ),
        }
        status = schema_status(engine)
    engine.dispose()
    print(f"{__app_name__} {__version__}  env={settings.environment}")
    print(f"data home: {settings.home}")
    print(f"database:  {settings.database_url}")
    print(f"schema:    {status['current']}/{status['latest']}")
    for key, value in counts.items():
        print(f"{key + ':':<14}{value}")
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

        assets = AssetService(db)
        threats = ThreatService(db)
        mes = assets.create(
            ctx,
            e1.id,
            name="生产执行系统 MES",
            asset_type="business",
            category="application",
            owner="王海",
            department="信息中心",
            location="总部园区 A 机房",
            confidentiality=3,
            integrity=3,
            availability=4,
            description="承载排产、工单与质量追溯，停机直接影响两条产线。",
        )
        erp = assets.create(
            ctx,
            e1.id,
            name="ERP 财务数据库",
            asset_type="business",
            category="database",
            owner="赵蕾",
            department="财务部",
            location="总部园区 A 机房",
            confidentiality=4,
            integrity=3,
            availability=3,
        )
        core_switch = assets.create(
            ctx,
            e1.id,
            name="园区核心交换机",
            asset_type="supporting",
            category="network",
            owner="孙鹏",
            department="信息中心",
            location="总部园区 A 机房",
            confidentiality=2,
            integrity=2,
            availability=4,
        )
        bastion = assets.create(
            ctx,
            e1.id,
            name="运维堡垒机",
            asset_type="supporting",
            category="server",
            owner="孙鹏",
            department="信息中心",
            location="总部园区 A 机房",
            confidentiality=3,
            integrity=4,
            availability=3,
            description="全部生产服务器运维入口，凭据集中托管。",
        )
        assets.create(
            ctx,
            e1.id,
            name="办公终端（120 台）",
            asset_type="supporting",
            category="endpoint",
            owner="行政部",
            department="行政部",
            location="总部与生产基地",
            confidentiality=2,
            integrity=1,
            availability=1,
        )

        ransomware = threats.create(
            ctx,
            e1.id,
            name="勒索软件加密生产数据",
            category="malicious",
            actor="external",
            description="通过钓鱼邮件或暴露面入侵后横向移动，加密数据库与文件服务器。",
        )
        phishing = threats.create(
            ctx,
            e1.id,
            name="钓鱼邮件窃取运维凭据",
            category="malicious",
            actor="external",
        )
        mistake = threats.create(
            ctx,
            e1.id,
            name="外包人员误操作导致配置丢失",
            category="insider",
            actor="third_party",
        )
        power = threats.create(
            ctx,
            e1.id,
            name="机房供电中断",
            category="environmental",
            actor="nature",
        )

        mes_ransom = assets.link_threat(
            ctx,
            mes.id,
            threat_id=ransomware.id,
            vulnerability="生产网与办公网未做 VLAN 隔离，终端可直接访问 MES 端口。",
            exposure="high",
        )
        bastion_phishing = assets.link_threat(
            ctx,
            bastion.id,
            threat_id=phishing.id,
            vulnerability="堡垒机未启用多因素认证，仅靠静态口令。",
            exposure="high",
        )
        erp_ransom = assets.link_threat(
            ctx,
            erp.id,
            threat_id=ransomware.id,
            vulnerability="数据库备份每日全量落本地 NAS，未做离线副本。",
            exposure="medium",
        )
        switch_power = assets.link_threat(
            ctx,
            core_switch.id,
            threat_id=power.id,
            vulnerability="机房 UPS 电池组已超服役年限，未做带载放电测试。",
            exposure="medium",
        )
        mes_mistake = assets.link_threat(
            ctx,
            mes.id,
            threat_id=mistake.id,
            vulnerability="变更窗口外允许直接操作生产配置，无审批留痕。",
            exposure="medium",
        )

        assessments = RiskAssessmentService(db)
        risks = RiskService(db)
        assessments.set_appetite(
            ctx,
            e1.id,
            max_acceptable_score=12,
            statement="残余分值不超过 12，超过需提交管理层评审。",
        )
        first = assessments.create(
            ctx,
            e1.id,
            title="2026 年首轮风险评估",
            assessor="演示顾问",
            summary="覆盖核心业务系统与支撑设施，按 5×5 矩阵完成首轮打分。",
        )
        first_scores = [
            (mes_ransom, 4, 4, 3, 3, "mitigate", "已完成生产网分区，离线备份待落地。"),
            (erp_ransom, 4, 5, 3, 4, "mitigate", "备份保留 30 天，异地副本仍在建设中。"),
            (bastion_phishing, 4, 4, 2, 3, "mitigate", "上线多因素认证后可显著降低凭据泄露影响。"),
            (switch_power, 2, 5, 2, 3, "mitigate", "更换 UPS 电池组并增加带载测试。"),
            (mes_mistake, 3, 3, 2, 2, "mitigate", "变更审批流已纳入运维平台。"),
        ]
        for link, likelihood, impact, residual_l, residual_i, treatment, rationale in first_scores:
            risks.add(
                ctx,
                first.id,
                asset_threat_id=link.id,
                likelihood=likelihood,
                impact=impact,
                residual_likelihood=residual_l,
                residual_impact=residual_i,
                treatment=treatment,
                rationale=rationale,
            )
        assessments.issue(ctx, first.id)

        second = assessments.create(
            ctx,
            e1.id,
            title="2026 年复评（草稿）",
            assessor="演示顾问",
            summary="复核首轮处置措施落地情况，供版本对比使用。",
        )
        second_scores = [
            (mes_ransom, 4, 4, 2, 3, "mitigate", "离线备份已上线，按月演练恢复。"),
            (erp_ransom, 4, 5, 3, 3, "mitigate", "异地副本完成，恢复演练通过。"),
            (bastion_phishing, 4, 4, 2, 2, "mitigate", "多因素认证覆盖全部运维账号。"),
            (switch_power, 2, 5, 1, 3, "mitigate", "电池组更换完成，季度带载测试。"),
            (mes_mistake, 3, 3, 2, 2, "accept", "客户接受残余风险，保留审批留痕。"),
        ]
        for link, likelihood, impact, residual_l, residual_i, treatment, rationale in second_scores:
            risks.add(
                ctx,
                second.id,
                asset_threat_id=link.id,
                likelihood=likelihood,
                impact=impact,
                residual_likelihood=residual_l,
                residual_impact=residual_i,
                treatment=treatment,
                rationale=rationale,
            )

        print("demo data loaded:")
        print(f"  clients:     {north.code}, {bank.code}, {clinic.code}")
        print(f"  engagements: {e1.code}, {e2.code}, {e3.code}")
        print(f"  assets:      {e1.code} 下有 5 项资产、4 类威胁、5 条关联")
        print(f"  risks:       {e1.code} 下有 2 个评估批次（1 已签发、1 草稿）")
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


def cmd_assets(args, settings: Settings) -> int:
    if args.assets_command == "template":
        text = csv_template()
        if args.out:
            args.out.write_text(text, encoding="utf-8")
            print(f"template written to {args.out}")
        else:
            sys.stdout.write(text)
        return 0

    engine, factory = _open(settings)
    try:
        with factory() as db:
            ctx = _cli_ctx(_operating_user(db))
            engagement = db.execute(
                select(Engagement).where(Engagement.code == args.engagement)
            ).scalar_one_or_none()
            if engagement is None:
                print(f"error: engagement not found: {args.engagement}", file=sys.stderr)
                return 2

            if args.assets_command == "import":
                if not args.file.exists():
                    print(f"error: file not found: {args.file}", file=sys.stderr)
                    return 2
                result = AssetImportService(db).import_bytes(
                    ctx,
                    engagement.id,
                    args.file.read_bytes(),
                    filename=args.file.name,
                )
                print(
                    f"imported {result['imported']}, skipped {result['skipped']}, "
                    f"failed {result['failed']}"
                )
                for error in result["errors"]:
                    print(f"  row {error['row']}: {error['message']}")
                return 0 if result["failed"] == 0 else 1

            rows, total, _, _ = AssetService(db).list(ctx, engagement.id, page_size=200)
            lines = [
                "code,name,asset_type,category,owner,department,location,"
                "confidentiality,integrity,availability,criticality,lifecycle_status"
            ]
            for row in rows:
                lines.append(
                    ",".join(
                        _csv_cell(value)
                        for value in (
                            row.code,
                            row.name,
                            row.asset_type,
                            row.category,
                            row.owner,
                            row.department,
                            row.location,
                            row.confidentiality,
                            row.integrity,
                            row.availability,
                            row.criticality,
                            row.lifecycle_status,
                        )
                    )
                )
            text = "\ufeff" + "\n".join(lines) + "\n"
            if args.out:
                args.out.write_text(text, encoding="utf-8")
                print(f"exported {total} assets to {args.out}")
            else:
                sys.stdout.write(text)
            return 0
    finally:
        engine.dispose()


def cmd_risks(args, settings: Settings) -> int:
    engine, factory = _open(settings)
    try:
        with factory() as db:
            ctx = _cli_ctx(_operating_user(db))
            engagement = db.execute(
                select(Engagement).where(Engagement.code == args.engagement)
            ).scalar_one_or_none()
            if engagement is None:
                print(f"error: engagement not found: {args.engagement}", file=sys.stderr)
                return 2

            service = RiskAssessmentService(db)
            if args.risks_command == "list":
                rows, _, _, _ = service.list(ctx, engagement.id, page_size=200)
                if not rows:
                    print(f"no assessments for {engagement.code}")
                    return 0
                print(f"{'code':<10}{'status':<8}{'items':<7}{'residual':<10}title")
                for row in rows:
                    stats = service.summary(ctx, row.id)
                    print(
                        f"{row.code:<10}{row.status:<8}{stats['total']:<7}"
                        f"{stats['average_residual']:<10}{row.title}"
                    )
                return 0

            assessment = db.execute(
                select(RiskAssessment).where(
                    RiskAssessment.engagement_id == engagement.id,
                    RiskAssessment.code == args.assessment,
                )
            ).scalar_one_or_none()
            if assessment is None:
                print(
                    f"error: assessment not found: {args.assessment}", file=sys.stderr
                )
                return 2

            lines = [
                "asset_code,asset_name,threat_code,threat_name,likelihood,impact,"
                "inherent_score,inherent_severity,residual_likelihood,residual_impact,"
                "residual_score,residual_severity,treatment,rationale"
            ]
            for item in service.items_for(assessment.id):
                lines.append(
                    ",".join(
                        _csv_cell(value)
                        for value in (
                            item.asset_code,
                            item.asset_name,
                            item.threat_code,
                            item.threat_name,
                            item.likelihood,
                            item.impact,
                            item.inherent_score,
                            item.inherent_severity,
                            item.residual_likelihood,
                            item.residual_impact,
                            item.residual_score,
                            item.residual_severity,
                            item.treatment,
                            item.rationale,
                        )
                    )
                )
            text = "\ufeff" + "\n".join(lines) + "\n"
            if args.out:
                args.out.write_text(text, encoding="utf-8")
                print(f"exported {len(lines) - 1} risks to {args.out}")
            else:
                sys.stdout.write(text)
            return 0
    finally:
        engine.dispose()


def _operating_user(db) -> User:
    """CLI actions need an actor; use the oldest active administrator."""
    admin = db.execute(
        select(User)
        .where(User.role == "admin", User.is_active.is_(True))
        .order_by(User.created_at.asc())
    ).scalars().first()
    if admin is None:
        raise NotFound("no active administrator; run create-admin first")
    return admin


def _csv_cell(value: object) -> str:
    text = "" if value is None else str(value)
    if any(char in text for char in ',"\n'):
        return '"' + text.replace('"', '""') + '"'
    return text


COMMANDS = {
    "init": cmd_init,
    "create-admin": cmd_create_admin,
    "create-user": cmd_create_user,
    "serve": cmd_serve,
    "status": cmd_status,
    "seed-demo": cmd_seed_demo,
    "prune-sessions": cmd_prune_sessions,
    "assets": cmd_assets,
    "risks": cmd_risks,
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
