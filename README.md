# AegisGRC

> 安全风险咨询工作台 —— 把咨询项目的客户、项目、干系人、审计留痕收进一个可离线运行的单机系统。

AegisGRC 面向独立安全顾问与小团队咨询方：不需要云服务、不需要外部数据库，一条命令初始化后即可在浏览器里管理客户主档、咨询项目生命周期和全过程审计。项目采用 MIT 协议开源。

## 当前进度

| 里程碑 | 范围 | 状态 |
|---|---|---|
| M1 | 平台基座：数据库迁移、认证与 RBAC、审计、客户/项目/干系人、Web 控制台、CLI | ✅ 已完成 |
| M2 | 资产与风险登记册：资产清单、风险矩阵、风险处置计划 | 规划中 |
| M3 | 控制库与合规映射：控制项、适用性声明 SoA、框架映射 | 规划中 |
| M4 | 访谈与证据：访谈记录、证据附件、发现项台账 | 规划中 |
| M5 | 报告与交付：报告生成、整改跟踪、客户门户 | 规划中 |
| M6 | 运营化：备份恢复、导入导出、指标看板、加固与发布 | 规划中 |

M1 只做"底座 + 主档"，不提前实现资产/风险/控制/报告，保证每个里程碑边界清晰、可验收。

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
| `consultant` | 客户/项目/干系人读写，审计只读 |
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

## 项目结构

```
aegis/
  api/            REST 路由、依赖注入、统一响应
  db/             引擎、自研迁移器、m0001_initial
  models/         SQLAlchemy 模型
  services/       业务规则与权限校验的唯一入口
  security/       口令哈希、令牌、RBAC、输入校验
  web/            Jinja2 服务端渲染路由
  templates/      14 个页面模板
  static/         原生 CSS/JS，无构建链
  config.py       环境配置与启动校验
  errors.py       统一错误码
  cli.py          运维命令
tests/            77 个用例，覆盖配置、迁移、安全、API、Web、CLI
docs/design/      设计取舍记录
```

## 测试

```bash
pytest            # 77 passed
```

测试使用内存 SQLite 与 `TestClient`，不依赖网络与外部服务，可在 CI 中直接运行。

## 设计取舍

见 [docs/design/m1-foundation.md](docs/design/m1-foundation.md)，其中记录了自研迁移器、单进程限流、Bearer 优先、审计同事务写入等决定的理由。

## 许可

MIT License，见 [LICENSE](LICENSE)。
