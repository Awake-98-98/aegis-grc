"""Control catalog, SoA and coverage console pages."""

from __future__ import annotations

from fastapi.testclient import TestClient


def _frameworks(client: TestClient, headers: dict) -> dict[str, dict]:
    rows = client.get("/api/frameworks", headers=headers).json()["data"]
    return {row["code"]: row for row in rows}


def _setup(client: TestClient, headers: dict) -> tuple[dict, dict, dict]:
    client.post("/api/clients", json={"name": "控制台客户"}, headers=headers)
    client_row = client.get("/api/clients").json()["data"][0]
    engagement = client.post(
        "/api/engagements",
        json={"client_id": client_row["id"], "name": "控制台项目"},
        headers=headers,
    ).json()["data"]
    asset = client.post(
        f"/api/engagements/{engagement['id']}/assets",
        json={"name": "核心数据库", "category": "database"},
        headers=headers,
    ).json()["data"]
    threat = client.post(
        f"/api/engagements/{engagement['id']}/threats",
        json={"name": "勒索软件", "category": "malicious"},
        headers=headers,
    ).json()["data"]
    link = client.post(
        f"/api/assets/{asset['id']}/threats",
        json={"threat_id": threat["id"], "vulnerability": "备份未离线"},
        headers=headers,
    ).json()["data"]
    assessment = client.post(
        f"/api/engagements/{engagement['id']}/assessments",
        json={"title": "控制台评估"},
        headers=headers,
    ).json()["data"]
    risk = client.post(
        f"/api/assessments/{assessment['id']}/risks",
        json={
            "asset_threat_id": link["id"],
            "likelihood": 4,
            "impact": 5,
            "residual_likelihood": 2,
            "residual_impact": 3,
        },
        headers=headers,
    ).json()["data"]
    return engagement, assessment, risk


def _soa_entries(
    client: TestClient, headers: dict, engagement_id: str, framework_id: str
) -> dict[str, dict]:
    rows = client.get(
        f"/api/engagements/{engagement_id}/soa",
        params={"framework_id": framework_id},
        headers=headers,
    ).json()["data"]
    return {row["control"]["code"]: row for row in rows}


def test_control_catalog_page(client: TestClient, bootstrap_admin: dict) -> None:
    page = client.get("/controls")
    assert page.status_code == 200
    assert "ISO/IEC 27001" in page.text
    assert "A.5.1" in page.text

    filtered = client.get("/controls", params={"q": "备份"})
    assert filtered.status_code == 200
    assert "A.8.13" in filtered.text

    domain = client.get("/controls", params={"domain": "A.6"})
    assert "人员控制" in domain.text
    assert "A.6.3" in domain.text


def test_soa_generate_and_edit_through_console(
    client: TestClient, bootstrap_admin: dict
) -> None:
    headers = {"X-CSRF-Token": bootstrap_admin["csrf_token"]}
    csrf = bootstrap_admin["csrf_token"]
    engagement, _, _ = _setup(client, headers)
    iso = _frameworks(client, headers)["ISO27001"]

    generated = client.post(
        f"/engagements/{engagement['id']}/soa/generate",
        data={"csrf_token": csrf, "framework_id": iso["id"]},
    )
    assert generated.status_code == 303

    page = client.get(
        f"/engagements/{engagement['id']}/soa",
        params={"framework_id": iso["id"]},
    )
    assert page.status_code == 200
    assert "框架覆盖率" in page.text
    assert "A.5.1" in page.text
    assert "未开始" in page.text

    entries = _soa_entries(client, headers, engagement["id"], iso["id"])
    saved = client.post(
        f"/soa/{entries['A.8.13']['id']}/edit",
        data={
            "csrf_token": csrf,
            "applicable": "on",
            "implementation_status": "implemented",
            "justification": "每日全量备份并保留离线副本",
            "owner": "运维组",
        },
    )
    assert saved.status_code == 303
    updated = _soa_entries(client, headers, engagement["id"], iso["id"])
    assert updated["A.8.13"]["implementation_status"] == "implemented"
    assert updated["A.8.13"]["owner"] == "运维组"

    refreshed = client.get(
        f"/engagements/{engagement['id']}/soa",
        params={"framework_id": iso["id"]},
    )
    assert "每日全量备份并保留离线副本" in refreshed.text

    excluded = client.post(
        f"/soa/{entries['A.7.4']['id']}/edit",
        data={
            "csrf_token": csrf,
            "implementation_status": "not_started",
            "justification": "",
            "owner": "",
        },
    )
    assert excluded.status_code == 422


def test_coverage_page_links_and_unlinks(
    client: TestClient, bootstrap_admin: dict
) -> None:
    headers = {"X-CSRF-Token": bootstrap_admin["csrf_token"]}
    csrf = bootstrap_admin["csrf_token"]
    _, assessment, risk = _setup(client, headers)
    iso = _frameworks(client, headers)["ISO27001"]
    control = client.get(
        f"/api/frameworks/{iso['id']}/controls",
        params={"q": "A.8.13"},
        headers=headers,
    ).json()["data"][0]

    empty = client.get(f"/assessments/{assessment['id']}/coverage")
    assert empty.status_code == 200
    assert "未覆盖风险" in empty.text
    assert "核心数据库" in empty.text
    assert "建立映射" in empty.text

    linked = client.post(
        f"/assessments/{assessment['id']}/controls",
        data={
            "csrf_token": csrf,
            "risk_id": risk["id"],
            "control_id": control["id"],
            "coverage": "full",
            "notes": "离线备份直接降低数据丢失",
        },
    )
    assert linked.status_code == 303

    covered = client.get(f"/assessments/{assessment['id']}/coverage")
    assert covered.status_code == 200
    assert "A.8.13" in covered.text
    assert "未覆盖风险" not in covered.text

    links = client.get(f"/api/risks/{risk['id']}/controls", headers=headers).json()["data"]
    removed = client.post(
        f"/risk-controls/{links[0]['id']}/delete", data={"csrf_token": csrf}
    )
    assert removed.status_code == 303
    assert "未覆盖风险" in client.get(f"/assessments/{assessment['id']}/coverage").text


def test_viewer_sees_read_only_pages(
    client: TestClient, bootstrap_admin: dict
) -> None:
    headers = {"X-CSRF-Token": bootstrap_admin["csrf_token"]}
    engagement, assessment, _ = _setup(client, headers)
    iso = _frameworks(client, headers)["ISO27001"]
    client.post(
        f"/engagements/{engagement['id']}/soa/generate",
        json={"framework_id": iso["id"]},
        headers=headers,
    )
    created = client.post(
        "/api/users",
        headers=headers,
        json={
            "email": "viewer-web@aegis.test",
            "display_name": "只读用户",
            "password": "MemberPass123",
            "role": "viewer",
        },
    )
    assert created.status_code == 201, created.text
    login = client.post(
        "/api/auth/login",
        json={"email": "viewer-web@aegis.test", "password": "MemberPass123"},
    )
    assert login.status_code == 200, login.text

    soa = client.get(
        f"/engagements/{engagement['id']}/soa",
        params={"framework_id": iso["id"]},
    )
    assert soa.status_code == 200
    assert "保存" not in soa.text

    coverage = client.get(f"/assessments/{assessment['id']}/coverage")
    assert coverage.status_code == 200
    assert "建立映射" not in coverage.text
