"""Schema v4: control frameworks, catalog, SoA entries and risk-control links.

The catalog is reference data. It is seeded once by this migration with stable
identifiers so tests and the CLI can address a control without guessing an
auto-incremented key. Statements of applicability and links are project data:
they reference the engagement or the scored risk item and disappear with it.
"""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import text
from sqlalchemy.engine import Connection

VERSION = 4
NAME = "control library and statement of applicability"

DDL = (
    """
    CREATE TABLE control_frameworks (
        id TEXT PRIMARY KEY,
        code TEXT NOT NULL UNIQUE,
        name TEXT NOT NULL,
        version TEXT NOT NULL DEFAULT '',
        publisher TEXT NOT NULL DEFAULT '',
        kind TEXT NOT NULL DEFAULT 'standard',
        description TEXT NOT NULL DEFAULT '',
        created_at DATETIME NOT NULL,
        updated_at DATETIME NOT NULL,
        CHECK (kind IN ('standard', 'framework', 'regulation'))
    )
    """,
    """
    CREATE TABLE controls (
        id TEXT PRIMARY KEY,
        framework_id TEXT NOT NULL REFERENCES control_frameworks(id) ON DELETE CASCADE,
        code TEXT NOT NULL,
        title TEXT NOT NULL,
        title_en TEXT NOT NULL DEFAULT '',
        domain TEXT NOT NULL DEFAULT '',
        domain_label TEXT NOT NULL DEFAULT '',
        guidance TEXT NOT NULL DEFAULT '',
        sort_order INTEGER NOT NULL DEFAULT 0,
        created_at DATETIME NOT NULL,
        updated_at DATETIME NOT NULL,
        UNIQUE (framework_id, code)
    )
    """,
    """
    CREATE TABLE soa_entries (
        id TEXT PRIMARY KEY,
        engagement_id TEXT NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
        control_id TEXT NOT NULL REFERENCES controls(id) ON DELETE CASCADE,
        applicable INTEGER NOT NULL DEFAULT 1,
        implementation_status TEXT NOT NULL DEFAULT 'not_started',
        justification TEXT NOT NULL DEFAULT '',
        owner TEXT NOT NULL DEFAULT '',
        notes TEXT NOT NULL DEFAULT '',
        updated_by TEXT REFERENCES users(id) ON DELETE SET NULL,
        created_at DATETIME NOT NULL,
        updated_at DATETIME NOT NULL,
        UNIQUE (engagement_id, control_id),
        CHECK (applicable IN (0, 1)),
        CHECK (implementation_status IN ('not_started', 'in_progress', 'implemented'))
    )
    """,
    """
    CREATE TABLE risk_control_links (
        id TEXT PRIMARY KEY,
        risk_item_id TEXT NOT NULL REFERENCES risk_items(id) ON DELETE CASCADE,
        control_id TEXT NOT NULL REFERENCES controls(id) ON DELETE CASCADE,
        coverage TEXT NOT NULL DEFAULT 'partial',
        notes TEXT NOT NULL DEFAULT '',
        created_by TEXT REFERENCES users(id) ON DELETE SET NULL,
        created_at DATETIME NOT NULL,
        updated_at DATETIME NOT NULL,
        UNIQUE (risk_item_id, control_id),
        CHECK (coverage IN ('full', 'partial', 'planned'))
    )
    """,
)

INDEXES = (
    "CREATE INDEX idx_controls_framework ON controls(framework_id)",
    "CREATE INDEX idx_controls_domain ON controls(framework_id, domain)",
    "CREATE INDEX idx_soa_entries_engagement ON soa_entries(engagement_id)",
    "CREATE INDEX idx_risk_control_risk ON risk_control_links(risk_item_id)",
    "CREATE INDEX idx_risk_control_control ON risk_control_links(control_id)",
)

FRAMEWORKS = (
    (
        "fw-iso27001-2022",
        "ISO27001",
        "ISO/IEC 27001:2022 附录 A",
        "2022",
        "ISO/IEC",
        "standard",
        "信息安全管理体系控制项，按组织、人员、物理、技术四个主题编排，共 93 项。",
    ),
    (
        "fw-nist-csf-2",
        "NISTCSF",
        "NIST 网络安全框架 2.0",
        "2.0",
        "NIST",
        "framework",
        "按治理、识别、保护、检测、响应、恢复六个功能编排，取类别级条目共 22 项。",
    ),
    (
        "fw-mlps-2",
        "MLPS",
        "网络安全等级保护 2.0",
        "2.0",
        "国家市场监督管理总局",
        "regulation",
        "安全通用要求，按 10 个安全域归纳控制点，共 70 项。",
    ),
)

ISO_ROWS = (
    ("A.5.1", "信息安全策略", "Policies for information security", "A.5", "组织控制"),
    (
        "A.5.2",
        "信息安全角色与职责",
        "Information security roles and responsibilities",
        "A.5",
        "组织控制",
    ),
    ("A.5.3", "职责分离", "Segregation of duties", "A.5", "组织控制"),
    ("A.5.4", "管理职责", "Management responsibilities", "A.5", "组织控制"),
    ("A.5.5", "与主管部门的联系", "Contact with authorities", "A.5", "组织控制"),
    (
        "A.5.6",
        "与专业团体的联系",
        "Contact with special interest groups",
        "A.5",
        "组织控制",
    ),
    ("A.5.7", "威胁情报", "Threat intelligence", "A.5", "组织控制"),
    (
        "A.5.8",
        "项目管理中的信息安全",
        "Information security in project management",
        "A.5",
        "组织控制",
    ),
    (
        "A.5.9",
        "信息及其他相关资产的清单",
        "Inventory of information and other associated assets",
        "A.5",
        "组织控制",
    ),
    (
        "A.5.10",
        "信息及其他相关资产的可接受使用",
        "Acceptable use of information and other associated assets",
        "A.5",
        "组织控制",
    ),
    ("A.5.11", "资产归还", "Return of assets", "A.5", "组织控制"),
    ("A.5.12", "信息分类", "Classification of information", "A.5", "组织控制"),
    ("A.5.13", "信息标记", "Labelling of information", "A.5", "组织控制"),
    ("A.5.14", "信息传输", "Information transfer", "A.5", "组织控制"),
    ("A.5.15", "访问控制", "Access control", "A.5", "组织控制"),
    ("A.5.16", "身份管理", "Identity management", "A.5", "组织控制"),
    ("A.5.17", "鉴别信息", "Authentication information", "A.5", "组织控制"),
    ("A.5.18", "访问权限", "Access rights", "A.5", "组织控制"),
    (
        "A.5.19",
        "供应商关系中的信息安全",
        "Information security in supplier relationships",
        "A.5",
        "组织控制",
    ),
    (
        "A.5.20",
        "供应商协议中的信息安全",
        "Addressing information security within supplier agreements",
        "A.5",
        "组织控制",
    ),
    (
        "A.5.21",
        "ICT 供应链中的信息安全管理",
        "Managing information security in the ICT supply chain",
        "A.5",
        "组织控制",
    ),
    (
        "A.5.22",
        "供应商服务的监视、评审与变更管理",
        "Monitoring, review and change management of supplier services",
        "A.5",
        "组织控制",
    ),
    (
        "A.5.23",
        "云服务使用中的信息安全",
        "Information security for use of cloud services",
        "A.5",
        "组织控制",
    ),
    (
        "A.5.24",
        "信息安全事件管理规划与准备",
        "Information security incident management planning and preparation",
        "A.5",
        "组织控制",
    ),
    (
        "A.5.25",
        "信息安全事态的评估与决策",
        "Assessment and decision on information security events",
        "A.5",
        "组织控制",
    ),
    (
        "A.5.26",
        "信息安全事件的响应",
        "Response to information security incidents",
        "A.5",
        "组织控制",
    ),
    (
        "A.5.27",
        "从信息安全事件中学习",
        "Learning from information security incidents",
        "A.5",
        "组织控制",
    ),
    ("A.5.28", "证据收集", "Collection of evidence", "A.5", "组织控制"),
    (
        "A.5.29",
        "中断期间的信息安全",
        "Information security during disruption",
        "A.5",
        "组织控制",
    ),
    (
        "A.5.30",
        "业务连续性的 ICT 准备",
        "ICT readiness for business continuity",
        "A.5",
        "组织控制",
    ),
    (
        "A.5.31",
        "法律、法规、监管与合同要求",
        "Legal, statutory, regulatory and contractual requirements",
        "A.5",
        "组织控制",
    ),
    ("A.5.32", "知识产权", "Intellectual property rights", "A.5", "组织控制"),
    ("A.5.33", "记录保护", "Protection of records", "A.5", "组织控制"),
    (
        "A.5.34",
        "隐私与个人身份信息保护",
        "Privacy and protection of PII",
        "A.5",
        "组织控制",
    ),
    (
        "A.5.35",
        "信息安全的独立评审",
        "Independent review of information security",
        "A.5",
        "组织控制",
    ),
    (
        "A.5.36",
        "信息安全方针、规则与标准的符合性",
        "Compliance with policies, rules and standards for information security",
        "A.5",
        "组织控制",
    ),
    (
        "A.5.37",
        "文件化的操作规程",
        "Documented operating procedures",
        "A.5",
        "组织控制",
    ),
    ("A.6.1", "人员筛选", "Screening", "A.6", "人员控制"),
    (
        "A.6.2",
        "雇佣条款与条件",
        "Terms and conditions of employment",
        "A.6",
        "人员控制",
    ),
    (
        "A.6.3",
        "信息安全意识、教育与培训",
        "Information security awareness, education and training",
        "A.6",
        "人员控制",
    ),
    ("A.6.4", "纪律处理过程", "Disciplinary process", "A.6", "人员控制"),
    (
        "A.6.5",
        "终止或变更雇佣后的职责",
        "Responsibilities after termination or change of employment",
        "A.6",
        "人员控制",
    ),
    (
        "A.6.6",
        "保密或不披露协议",
        "Confidentiality or non-disclosure agreements",
        "A.6",
        "人员控制",
    ),
    ("A.6.7", "远程工作", "Remote working", "A.6", "人员控制"),
    (
        "A.6.8",
        "信息安全事件报告",
        "Information security event reporting",
        "A.6",
        "人员控制",
    ),
    (
        "A.7.1",
        "物理安全边界",
        "Physical security perimeters",
        "A.7",
        "物理控制",
    ),
    ("A.7.2", "物理入口", "Physical entry", "A.7", "物理控制"),
    (
        "A.7.3",
        "办公室、房间与设施的安全",
        "Securing offices, rooms and facilities",
        "A.7",
        "物理控制",
    ),
    (
        "A.7.4",
        "物理安全监视",
        "Physical security monitoring",
        "A.7",
        "物理控制",
    ),
    (
        "A.7.5",
        "防范物理与环境威胁",
        "Protecting against physical and environmental threats",
        "A.7",
        "物理控制",
    ),
    ("A.7.6", "在安全区域工作", "Working in secure areas", "A.7", "物理控制"),
    (
        "A.7.7",
        "清桌面与清屏幕",
        "Clear desk and clear screen",
        "A.7",
        "物理控制",
    ),
    (
        "A.7.8",
        "设备安置与保护",
        "Equipment siting and protection",
        "A.7",
        "物理控制",
    ),
    (
        "A.7.9",
        "场外资产的安全",
        "Security of assets off-premises",
        "A.7",
        "物理控制",
    ),
    ("A.7.10", "存储介质", "Storage media", "A.7", "物理控制"),
    ("A.7.11", "支持性设施", "Supporting utilities", "A.7", "物理控制"),
    ("A.7.12", "布缆安全", "Cabling security", "A.7", "物理控制"),
    ("A.7.13", "设备维护", "Equipment maintenance", "A.7", "物理控制"),
    (
        "A.7.14",
        "设备的安全处置或再利用",
        "Secure disposal or re-use of equipment",
        "A.7",
        "物理控制",
    ),
    (
        "A.8.1",
        "用户终端设备",
        "User endpoint devices",
        "A.8",
        "技术控制",
    ),
    ("A.8.2", "特权访问权限", "Privileged access rights", "A.8", "技术控制"),
    (
        "A.8.3",
        "信息访问限制",
        "Information access restriction",
        "A.8",
        "技术控制",
    ),
    ("A.8.4", "源代码访问", "Access to source code", "A.8", "技术控制"),
    ("A.8.5", "安全鉴别", "Secure authentication", "A.8", "技术控制"),
    ("A.8.6", "容量管理", "Capacity management", "A.8", "技术控制"),
    ("A.8.7", "恶意软件防护", "Protection against malware", "A.8", "技术控制"),
    (
        "A.8.8",
        "技术脆弱性管理",
        "Management of technical vulnerabilities",
        "A.8",
        "技术控制",
    ),
    ("A.8.9", "配置管理", "Configuration management", "A.8", "技术控制"),
    ("A.8.10", "信息删除", "Information deletion", "A.8", "技术控制"),
    ("A.8.11", "数据掩码", "Data masking", "A.8", "技术控制"),
    (
        "A.8.12",
        "数据泄露防护",
        "Data leakage prevention",
        "A.8",
        "技术控制",
    ),
    ("A.8.13", "信息备份", "Information backup", "A.8", "技术控制"),
    (
        "A.8.14",
        "信息处理设施冗余",
        "Redundancy of information processing facilities",
        "A.8",
        "技术控制",
    ),
    ("A.8.15", "日志记录", "Logging", "A.8", "技术控制"),
    ("A.8.16", "监视活动", "Monitoring activities", "A.8", "技术控制"),
    ("A.8.17", "时钟同步", "Clock synchronization", "A.8", "技术控制"),
    (
        "A.8.18",
        "特权实用程序的使用",
        "Use of privileged utility programs",
        "A.8",
        "技术控制",
    ),
    (
        "A.8.19",
        "运行系统上的软件安装",
        "Installation of software on operational systems",
        "A.8",
        "技术控制",
    ),
    ("A.8.20", "网络安全", "Networks security", "A.8", "技术控制"),
    (
        "A.8.21",
        "网络服务的安全",
        "Security of network services",
        "A.8",
        "技术控制",
    ),
    ("A.8.22", "网络隔离", "Segregation of networks", "A.8", "技术控制"),
    ("A.8.23", "网页过滤", "Web filtering", "A.8", "技术控制"),
    ("A.8.24", "密码技术的使用", "Use of cryptography", "A.8", "技术控制"),
    (
        "A.8.25",
        "安全开发生命周期",
        "Secure development life cycle",
        "A.8",
        "技术控制",
    ),
    (
        "A.8.26",
        "应用安全要求",
        "Application security requirements",
        "A.8",
        "技术控制",
    ),
    (
        "A.8.27",
        "安全系统架构与工程原则",
        "Secure system architecture and engineering principles",
        "A.8",
        "技术控制",
    ),
    ("A.8.28", "安全编码", "Secure coding", "A.8", "技术控制"),
    (
        "A.8.29",
        "开发与验收中的安全测试",
        "Security testing in development and acceptance",
        "A.8",
        "技术控制",
    ),
    ("A.8.30", "外包开发", "Outsourced development", "A.8", "技术控制"),
    (
        "A.8.31",
        "开发、测试与生产环境的分离",
        "Separation of development, test and production environments",
        "A.8",
        "技术控制",
    ),
    ("A.8.32", "变更管理", "Change management", "A.8", "技术控制"),
    ("A.8.33", "测试信息", "Test information", "A.8", "技术控制"),
    (
        "A.8.34",
        "审计测试期间信息系统的保护",
        "Protection of information systems during audit testing",
        "A.8",
        "技术控制",
    ),
)

NIST_ROWS = (
    ("GV.OC", "组织背景", "Organizational Context", "GV", "治理"),
    ("GV.RM", "风险管理策略", "Risk Management Strategy", "GV", "治理"),
    (
        "GV.RR",
        "角色、职责与权限",
        "Roles, Responsibilities, and Authorities",
        "GV",
        "治理",
    ),
    ("GV.PO", "策略", "Policy", "GV", "治理"),
    ("GV.OV", "监督", "Oversight", "GV", "治理"),
    (
        "GV.SC",
        "供应链风险管理",
        "Supply Chain Risk Management",
        "GV",
        "治理",
    ),
    ("ID.AM", "资产管理", "Asset Management", "ID", "识别"),
    ("ID.RA", "风险评估", "Risk Assessment", "ID", "识别"),
    ("ID.IM", "改进", "Improvement", "ID", "识别"),
    (
        "PR.AA",
        "身份管理与访问控制",
        "Identity Management, Authentication, and Access Control",
        "PR",
        "保护",
    ),
    ("PR.AT", "意识与培训", "Awareness and Training", "PR", "保护"),
    ("PR.DS", "数据安全", "Data Security", "PR", "保护"),
    ("PR.PS", "平台安全", "Platform Security", "PR", "保护"),
    (
        "PR.IR",
        "技术基础设施韧性",
        "Technology Infrastructure Resilience",
        "PR",
        "保护",
    ),
    ("DE.AE", "不良事件分析", "Adverse Event Analysis", "DE", "检测"),
    ("DE.CM", "持续监控", "Continuous Monitoring", "DE", "检测"),
    ("RS.MA", "事件管理", "Incident Management", "RS", "响应"),
    ("RS.AN", "事件分析", "Incident Analysis", "RS", "响应"),
    (
        "RS.CO",
        "事件响应报告与沟通",
        "Incident Response Reporting and Communication",
        "RS",
        "响应",
    ),
    ("RS.MI", "事件缓解", "Incident Mitigation", "RS", "响应"),
    (
        "RC.RP",
        "事件恢复计划执行",
        "Incident Recovery Plan Execution",
        "RC",
        "恢复",
    ),
    ("RC.CO", "恢复沟通", "Recovery Communication", "RC", "恢复"),
)

MLPS_ROWS = (
    ("PE", "安全物理环境", (
        "物理位置选择",
        "物理访问控制",
        "防盗窃和防破坏",
        "防雷击",
        "防火",
        "防水和防潮",
        "温湿度控制",
        "电力供应",
        "电磁防护",
    )),
    ("CN", "安全通信网络", ("网络架构", "通信传输", "可信验证")),
    ("AB", "安全区域边界", (
        "边界防护",
        "访问控制",
        "入侵防范",
        "恶意代码防范",
        "安全审计",
        "可信验证",
    )),
    ("CE", "安全计算环境", (
        "身份鉴别",
        "访问控制",
        "安全审计",
        "入侵防范",
        "恶意代码防范",
        "可信验证",
        "数据完整性",
        "数据保密性",
        "数据备份恢复",
        "剩余信息保护",
        "个人信息保护",
    )),
    ("MC", "安全管理中心", ("系统管理", "审计管理", "安全管理", "集中管控")),
    ("PS", "安全管理制度", ("安全策略", "管理制度", "制定和发布", "评审和修订")),
    ("PO", "安全管理机构", (
        "岗位设置",
        "人员配备",
        "授权和审批",
        "沟通和合作",
        "审核和检查",
    )),
    ("PM", "安全管理人员", (
        "人员录用",
        "人员离岗",
        "安全意识教育和培训",
        "外部人员访问管理",
    )),
    ("CB", "安全建设管理", (
        "定级和备案",
        "安全方案设计",
        "产品采购和使用",
        "自行软件开发",
        "外包软件开发",
        "工程实施",
        "测试验收",
        "系统交付",
        "等级测评",
        "服务供应商选择",
    )),
    ("OM", "安全运维管理", (
        "环境管理",
        "资产管理",
        "介质管理",
        "设备维护管理",
        "漏洞和风险管理",
        "网络和系统安全管理",
        "恶意代码防范管理",
        "配置管理",
        "密码管理",
        "变更管理",
        "备份与恢复管理",
        "安全事件处置",
        "应急预案管理",
        "外包运维管理",
    )),
)


def _id(framework: str, code: str) -> str:
    return f"{framework}-{code.lower().replace('.', '-')}"


def _control_rows() -> list[tuple]:
    rows: list[tuple] = []
    for index, (code, title, title_en, domain, domain_label) in enumerate(ISO_ROWS):
        rows.append(
            (
                _id("iso", code),
                "fw-iso27001-2022",
                code,
                title,
                title_en,
                domain,
                domain_label,
                "",
                index,
            )
        )
    for index, (code, title, title_en, domain, domain_label) in enumerate(NIST_ROWS):
        rows.append(
            (
                _id("nist", code),
                "fw-nist-csf-2",
                code,
                title,
                title_en,
                domain,
                domain_label,
                "",
                index,
            )
        )
    order = 0
    for domain, domain_label, titles in MLPS_ROWS:
        for index, title in enumerate(titles, start=1):
            code = f"{domain}-{index:02d}"
            rows.append(
                (
                    _id("mlps", code),
                    "fw-mlps-2",
                    code,
                    title,
                    "",
                    domain,
                    domain_label,
                    "",
                    order,
                )
            )
            order += 1
    return rows


def apply(connection: Connection) -> None:
    for statement in DDL:
        connection.execute(text(statement))
    for statement in INDEXES:
        connection.execute(text(statement))

    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")
    connection.execute(
        text(
            "INSERT INTO control_frameworks ("
            "id, code, name, version, publisher, kind, description, created_at, updated_at"
            ") VALUES ("
            ":id, :code, :name, :version, :publisher, :kind, :description, :created_at, :updated_at"
            ")"
        ),
        [
            {
                "id": row[0],
                "code": row[1],
                "name": row[2],
                "version": row[3],
                "publisher": row[4],
                "kind": row[5],
                "description": row[6],
                "created_at": now,
                "updated_at": now,
            }
            for row in FRAMEWORKS
        ],
    )
    connection.execute(
        text(
            "INSERT INTO controls ("
            "id, framework_id, code, title, title_en, domain, domain_label, "
            "guidance, sort_order, created_at, updated_at"
            ") VALUES ("
            ":id, :framework_id, :code, :title, :title_en, :domain, :domain_label, "
            ":guidance, :sort_order, :created_at, :updated_at"
            ")"
        ),
        [
            {
                "id": row[0],
                "framework_id": row[1],
                "code": row[2],
                "title": row[3],
                "title_en": row[4],
                "domain": row[5],
                "domain_label": row[6],
                "guidance": row[7],
                "sort_order": row[8],
                "created_at": now,
                "updated_at": now,
            }
            for row in _control_rows()
        ],
    )
