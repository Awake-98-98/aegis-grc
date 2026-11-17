# AegisGRC

> 安全风险咨询工作台：把咨询项目的客户、资产、项目进度和审计留痕收进一个可离线运行的单机系统。

AegisGRC 面向独立安全顾问与小团队咨询方：不需要云服务、不需要外部数据库，一条命令初始化后即可在浏览器里管理客户主档、咨询项目、资产清单与全过程审计。项目采用 MIT 协议开源。

## 当前进度

| 里程碑 | 范围 | 状态 |
|---|---|---|
| M1 | 平台基座：数据库迁移、认证与 RBAC、审计、客户/项目/干系人、Web 控制台、CLI | 已完成 |
| M2 | 资产与威胁面：资产清单、CIA 分级、威胁目录、资产威胁配对、CSV 导入导出 | 已完成 |
| M3 | 风险评估：可能性与影响矩阵、固有/剩余风险、处置策略 | 已完成 |
| M4 | 控制库与合规映射：控制项、适用性声明 SoA、框架映射 | 已完成 |
| M5 | 访谈、证据与整改：访谈记录、证据附件、整改任务 | 规划中 |
| M6 | 报告与运营：报告生成、备份恢复、指标看板、加固与发布 | 规划中 |

每个里程碑只做自己那一段，不提前实现后续能力。M2 交付资产台账与威胁面，M3 交付评估批次与风险登记册，M4 交付控制库、适用性声明与风险覆盖，证据与整改留给 M5。

## 快速开始

要求 Python 3.12+（开发使用 3.13）。

```bash
# 1. 创建虚拟环境并安装
python -m venv .venv
.venv\Scripts\activate            # Windows
pip install -e ".[dev]"

# 2. 初始化数据库（默认数据目录 ./aegis-data）
aegis init

# 3. 创建第一个管理员（也可用交互式输入，避免密码进 shell 历史）
set AEGIS_ADMIN_PASSWORD=YourStrongPass123
aegis create-admin --email you@example.com --display-name "你的名字"

# 4. 可选：载入虚构演示数据
aegis seed-demo

# 5. 启动 Web 控制台
aegis serve
```

打开 http://127.0.0.1:8000 ，首次访问会自动跳转 `/setup` 完成初始化。

常用命令：

```bash
aegis status           # 查看 schema 版本、各表记录数与数据库位置
aegis create-user --email a@b.c --display-name "顾问甲" --role consultant
aegis prune-sessions   # 清理过期/已吊销会话
aegis serve --port 8080 --reload

aegis assets template --out assets.csv
aegis assets import --engagement ENG-2026-0001 --file assets.csv
aegis assets export --engagement ENG-2026-0001 --out exported.csv

aegis risks list --engagement ENG-2026-0001
aegis risks export --engagement ENG-2026-0001 --assessment RA-0001 --out register.csv

aegis controls frameworks
aegis controls list --framework ISO27001 --domain A.8
aegis controls coverage --engagement ENG-2026-0001 --assessment RA-0001
aegis soa generate --engagement ENG-2026-0001 --framework ISO27001
aegis soa export --engagement ENG-2026-0001 --framework ISO27001 --out soa.csv
```

## 配置

全部通过环境变量，均有安全默认值：

| 变量 | 默认 | 说明 |
|---|---|---|
| `AEGIS_HOME` | `./aegis-data` | 数据目录，存放 SQLite 与 `secret.key` |
| `AEGIS_ENV` | `dev` | `dev` / `production`，生产环境强制更严格校验 |
| `AEGIS_HOST` / `AEGIS_PORT` | `127.0.0.1` / `8000` | 监听地址 |
| `AEGIS_SESSION_TTL_HOURS` | `8` | 会话有效期 |
| `AEGIS_COOKIE_SECURE` | 生产为 `true` | 是否仅在 HTTPS 下发送 Cookie |
| `AEGIS_SECRET_KEY` | 自动生成 | 可覆盖，生产要求 ≥32 字符 |
| `AEGIS_ADMIN_PASSWORD` | 无 | `create-admin` 的非交互密码来源 |

## 角色与权限

| 角色 | 权限 |
|---|---|
| `admin` | `*`，含用户管理与全部写操作 |
| `consultant` | 客户/项目/干系人/资产/威胁/风险/控制读写，审计只读 |
| `viewer` | 全部只读 |

权限在服务层统一判定（`aegis/security/rbac.py`），Web 与 REST 共用同一套规则，避免两处实现漂移。

## REST API 摘要

统一响应结构：

```json
{"ok": true, "data": ..., "meta": {"page": 1, "page_size": 20, "total": 3, "pages": 1}}
```

失败时：

```json
{"ok": false, "error": {"code": "AEG-4001", "message": "...", "details": {...}}, "request_id": "..."}
```

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/api/health` | 健康检查（含 schema 版本、数据库连通性） |
| GET | `/api/setup/status` | 是否已完成初始化 |
| POST | `/api/auth/bootstrap` | 首次创建管理员（仅空库可用） |
| POST | `/api/auth/login` | 登录，返回 `token`、`csrf_token`、`expires_at` |
| POST | `/api/auth/logout` | 注销当前会话 |
| GET | `/api/auth/me` | 当前用户与会话信息 |
| POST | `/api/auth/change-password` | 修改自己的密码 |
| GET/POST | `/api/users` | 用户列表 / 创建用户（管理员） |
| GET/POST | `/api/clients` | 客户列表（搜索、分页）/ 创建 |
| GET/PATCH/DELETE | `/api/clients/{id}` | 客户详情 / 更新 / 归档 |
| GET/POST | `/api/engagements` | 项目列表（按状态、客户过滤）/ 创建 |
| GET/PATCH | `/api/engagements/{id}` | 项目详情 / 更新 |
| POST | `/api/engagements/{id}/transition` | 状态流转 |
| GET/POST | `/api/clients/{id}/stakeholders` | 干系人列表 / 新增 |
| PATCH/DELETE | `/api/stakeholders/{id}` | 干系人更新 / 删除 |
| GET/POST | `/api/engagements/{id}/assets` | 资产列表（搜索、类别、关键度）/ 登记 |
| GET/PATCH/DELETE | `/api/assets/{id}` | 资产详情 / 更新 / 删除 |
| GET | `/api/engagements/{id}/assets/summary` | 资产画像（按类别、类型、关键度统计） |
| POST | `/api/engagements/{id}/assets/import` | 上传 CSV 导入资产（multipart） |
| GET | `/api/assets/template.csv` | 下载导入模板 |
| GET/POST | `/api/engagements/{id}/threats` | 威胁目录 / 登记威胁 |
| GET/PATCH/DELETE | `/api/threats/{id}` | 威胁详情 / 更新 / 删除 |
| GET/POST | `/api/assets/{id}/threats` | 资产已关联威胁 / 关联一条威胁 |
| PATCH/DELETE | `/api/asset-threats/{id}` | 更新 / 解除关联 |
| GET/POST | `/api/engagements/{id}/assessments` | 评估批次列表 / 新建 |
| GET/PUT | `/api/engagements/{id}/risk-appetite` | 读取 / 设置风险偏好 |
| GET/PATCH/DELETE | `/api/assessments/{id}` | 批次详情 / 更新 / 删除（仅草稿） |
| POST | `/api/assessments/{id}/issue` | 签发批次并冻结 |
| GET | `/api/assessments/{id}/summary` | 批次汇总（分档、处置、均值、超偏好数） |
| GET | `/api/assessments/{id}/compare/{baseline_id}` | 与基线批次逐项对比 |
| GET/POST | `/api/assessments/{id}/risks` | 风险项列表 / 新增评分 |
| GET/PATCH/DELETE | `/api/risks/{id}` | 风险项详情 / 更新 / 删除 |
| GET | `/api/frameworks` | 控制框架列表与条目数 |
| GET | `/api/frameworks/{id}` | 框架详情与安全域统计 |
| GET | `/api/frameworks/{id}/controls` | 控制项列表（搜索、安全域、分页） |
| GET | `/api/controls/{id}` | 控制项详情 |
| GET | `/api/engagements/{id}/soa` | 项目适用性声明（按框架） |
| GET | `/api/engagements/{id}/soa/summary` | SoA 覆盖率汇总 |
| POST | `/api/engagements/{id}/soa/generate` | 补齐缺失的 SoA 条目 |
| PATCH | `/api/soa/{id}` | 更新适用性、实施状态、理由、责任人 |
| GET | `/api/assessments/{id}/coverage` | 风险控制覆盖与未覆盖清单 |
| GET/POST | `/api/risks/{id}/controls` | 风险项已挂控制 / 建立映射 |
| DELETE | `/api/risk-controls/{id}` | 解除映射 |
| GET | `/api/audit` | 审计事件查询（实体、动作、操作人、分页） |
| GET | `/api/dashboard/summary` | 看板聚合数据 |

认证方式二选一：

- **Cookie 会话**：`aegis_session`，HttpOnly、SameSite=Lax，写操作需带 `X-CSRF-Token` 或表单 `csrf_token`。
- **Bearer Token**：`Authorization: Bearer <token>`，优先于 Cookie，适合脚本与集成。

## 项目状态机

```
draft → scoping → fieldwork → reporting → closed → archived
```

非法流转返回 `AEG-4001`。终态 `archived` 不可再流转，保证历史项目不被误改。

## 资产与威胁

资产挂在项目下，编号为项目内自增的 `AST-0001`。每项资产记录机密性、完整性、可用性三个 1–4 级赋值：

- 关键度取三者最高档：任一为 4 即 `critical`，最高为 3 为 `high`，最高为 2 为 `medium`，全为 1 为 `low`。
- 优先级分为 `C×3 + I×2 + A×2`，范围 7–28，用于列表默认排序。

威胁目录同样按项目维护，编号 `THR-0001`。资产与威胁通过配对表关联，每条关联记录具体薄弱点与暴露程度（`low`/`medium`/`high`）。M2 只记录配对，不计算风险值。

CSV 导入接受英文或中文表头，中文取值（如"业务资产""在用"）会自动映射；同名资产跳过而不覆盖，单次上限 1000 行，逐行报告错误。

## 风险评估

评估以批次（`RA-0001`）为单位，一个项目可以有多个批次，例如"2026 年度初评""整改后复评"。批次有两种状态：

- `draft`：可增删改评分项，供顾问反复调整；
- `issued`：签发后冻结，评分项、批次信息都不能再改，也不能重复签发。

批次作为版本单元，是为了让报告引用的数字可以复现。改口径时新建一个批次，而不是覆盖历史。

### 5×5 矩阵

可能性与影响各取 1–5，分值 `L × I`（1–25），分四档：

| 分值 | 等级 | 含义 |
|---|---|---|
| 1–4 | 低 | 可接受，常规流程处理 |
| 5–9 | 中 | 需要明确责任人 |
| 10–15 | 高 | 需要处置计划 |
| 16–25 | 严重 | 需要管理层决策 |

每个评分项同时记录固有（处置前）与残余（处置后）两套 L/I。新建时残余默认等于固有；填写处置理由后通常把残余调低。风险降幅由两者差值计算。

处置策略四选一：缓解、接受、转移、规避。

### 风险偏好

项目级设置一个可接受分值上限，默认 9（中档上界）。评分项的残余分超过上限时标记为"超出偏好"，在详情页和汇总接口中单独计数。偏好只有一个阈值，不做按类别或按资产的分级偏好。

### 版本对比

同一项目的两个批次可以逐项对比。匹配键是快照中的资产编号与威胁编号，而不是数据库主键，因此资产改名后仍能对应。结果分为新增、移除、变化、未变四类，并统计残余分升高与降低的条数。

风险项保存资产与威胁的编号、名称快照，关联外键为 `SET NULL`。资产或威胁被删除后，已签发的登记册仍然可读。

## 控制库与合规映射

内置三套控制框架，迁移时写入，界面只读：

| 框架 | 代码 | 条目 |
|---|---|---|
| ISO/IEC 27001:2022 附录 A | `ISO27001` | 93 |
| NIST CSF 2.0 | `NISTCSF` | 22 |
| 等保 2.0 安全通用要求 | `MLPS` | 70 |

NIST 取六个功能下的类别，不展开 106 条子类；等保按 10 个安全域归纳控制点。ISO 与 NIST 保留英文原题。

### 适用性声明

项目按框架生成 SoA，每个控制项记录是否适用、实施状态（未开始/进行中/已实施）、理由与责任人。生成只补缺失条目，重复执行不会覆盖已有判断。

排除控制项必须填写理由，且不能标为已实施，否则返回 422 `AEG-2003`。框架覆盖率 = 已实施适用项 / 适用项，不适用项不计入分母。

### 风险控制映射

控制项挂到评分项上，覆盖程度分完全覆盖、部分覆盖、计划覆盖。映射随评估批次走，新批次不自动继承，避免新版风险凭空显示已覆盖。

批次覆盖接口返回逐条风险的控制映射、按框架的覆盖计数与未覆盖清单。风险覆盖率 = 至少一条映射的评分项 / 批次评分项总数。

Web 控制台在"控制库"浏览目录，项目详情进入"适用性声明"，评估详情进入"控制覆盖"。

## 项目结构

```
aegis/
  api/            REST 路由、依赖注入、统一响应
  db/             引擎、自研迁移器、m0001 至 m0004
  models/         SQLAlchemy 模型
  risk/           5×5 矩阵常量与分档函数
  services/       业务规则与权限校验的唯一入口
  security/       口令哈希、令牌、RBAC、输入校验
  web/            Jinja2 服务端渲染路由
  templates/      24 个页面模板
  static/         原生 CSS/JS，无构建链
  config.py       环境配置与启动校验
  errors.py       统一错误码
  cli.py          运维命令
tests/            148 个用例，覆盖配置、迁移、安全、API、Web、CLI
docs/design/      设计取舍记录
```

## 测试

```bash
pytest            # 148 passed
```

测试使用内存 SQLite 与 `TestClient`，不依赖网络与外部服务，可在 CI 中直接运行。

## 设计取舍

按里程碑记录：

- [m1-foundation.md](docs/design/m1-foundation.md)：自研迁移器、单进程限流、Bearer 优先、审计同事务写入
- [m2-assets.md](docs/design/m2-assets.md)：资产挂项目、派生分不落库、导入部分成功
- [m3-risks.md](docs/design/m3-risks.md)：批次冻结、快照匹配、单一偏好阈值
- [m4-controls.md](docs/design/m4-controls.md)：全局目录、惰性 SoA、排除理由、映射随批次、两个覆盖率口径

## 许可

MIT License，见 [LICENSE](LICENSE)。
