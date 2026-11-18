"""Control catalog, statement of applicability and coverage API."""

from __future__ import annotations

from fastapi.testclient import TestClient


def _frameworks(client: TestClient, headers: dict) -> dict[str, dict]:
    rows = client.get("/api/frameworks", headers=headers).json()["data"]
    return {row["code"]: row for row in rows}


def _control(client: TestClient, headers: dict, framework_id: str, code: str) -> dict:
    rows = client.get(
        f"/api/frameworks/{framework_id}/controls",
        params={"q": code, "page_size": 200},
        headers=headers,
    ).json()["data"]
    return next(row for row in rows if row["code"] == code)


def _setup(client: TestClient, headers: dict) -> tuple[dict, dict, dict]:
    client.post("/api/clients", json={"name": "控制库客户"}, headers=headers)
    client_row = client.get("/api/clients").json()["data"][0]
    engagement = client.post(
        "/api/engagements",
        json={"client_id": client_row["id"], "name": "控制库项目"},
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
        json={"title": "首轮评估"},
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


def test_catalog_contains_three_frameworks(
    client: TestClient, admin_headers: dict
) -> None:
    frameworks = _frameworks(client, admin_headers)
    assert set(frameworks) == {"ISO27001", "NISTCSF", "MLPS"}
    assert frameworks["ISO27001"]["control_count"] == 93
    assert frameworks["NISTCSF"]["control_count"] == 22
    assert frameworks["MLPS"]["control_count"] == 70

    iso = frameworks["ISO27001"]
    detail = client.get(f"/api/frameworks/{iso['id']}", headers=admin_headers)
    assert detail.status_code == 200
    assert len(detail.json()["data"]["domains"]) == 4

    mlps = frameworks["MLPS"]
    mlps_detail = client.get(f"/api/frameworks/{mlps['id']}", headers=admin_headers)
    assert len(mlps_detail.json()["data"]["domains"]) == 10


def test_control_search_and_domain_filter(
    client: TestClient, admin_headers: dict
) -> None:
    iso = _frameworks(client, admin_headers)["ISO27001"]
    found = client.get(
        f"/api/frameworks/{iso['id']}/controls",
        params={"q": "备份"},
        headers=admin_headers,
    ).json()["data"]
    assert any(row["code"] == "A.8.13" for row in found)

    technical = client.get(
        f"/api/frameworks/{iso['id']}/controls",
        params={"domain": "A.8", "page_size": 200},
        headers=admin_headers,
    )
    assert technical.status_code == 200
    assert technical.json()["meta"]["total"] == 34
    assert all(row["domain"] == "A.8" for row in technical.json()["data"])

    detail = client.get(f"/api/controls/{found[0]['id']}", headers=admin_headers)
    assert detail.status_code == 200
    assert detail.json()["data"]["framework_code"] == "ISO27001"


def test_soa_generation_is_idempotent(
    client: TestClient, admin_headers: dict
) -> None:
    engagement, _, _ = _setup(client, admin_headers)
    iso = _frameworks(client, admin_headers)["ISO27001"]

    first = client.post(
        f"/api/engagements/{engagement['id']}/soa/generate",
        json={"framework_id": iso["id"]},
        headers=admin_headers,
    )
    assert first.status_code == 200, first.text
    assert first.json()["data"] == {"created": 93, "skipped": 0, "total": 93}

    second = client.post(
        f"/api/engagements/{engagement['id']}/soa/generate",
        json={"framework_id": iso["id"]},
        headers=admin_headers,
    )
    assert second.json()["data"] == {"created": 0, "skipped": 93, "total": 93}

    summary = client.get(
        f"/api/engagements/{engagement['id']}/soa/summary",
        params={"framework_id": iso["id"]},
        headers=admin_headers,
    ).json()["data"]
    assert summary["generated"] == 93
    assert summary["applicable"] == 93
    assert summary["coverage_pct"] == 0.0

    entries = client.get(
        f"/api/engagements/{engagement['id']}/soa",
        params={"framework_id": iso["id"]},
        headers=admin_headers,
    ).json()
    assert entries["meta"]["total"] == 93
    assert entries["data"][0]["control"]["code"] == "A.5.1"


def test_exclusion_requires_justification(
    client: TestClient, admin_headers: dict
) -> None:
    engagement, _, _ = _setup(client, admin_headers)
    iso = _frameworks(client, admin_headers)["ISO27001"]
    client.post(
        f"/api/engagements/{engagement['id']}/soa/generate",
        json={"framework_id": iso["id"]},
        headers=admin_headers,
    )
    entries = client.get(
        f"/api/engagements/{engagement['id']}/soa",
        params={"framework_id": iso["id"]},
        headers=admin_headers,
    ).json()["data"]
    entry = entries[0]

    empty = client.patch(
        f"/api/soa/{entry['id']}",
        json={"applicable": False},
        headers=admin_headers,
    )
    assert empty.status_code == 422
    assert empty.json()["error"]["code"] == "AEG-2003"

    implemented = client.patch(
        f"/api/soa/{entry['id']}",
        json={
            "applicable": False,
            "implementation_status": "implemented",
            "justification": "由集团统一提供",
        },
        headers=admin_headers,
    )
    assert implemented.status_code == 422

    excluded = client.patch(
        f"/api/soa/{entry['id']}",
        json={
            "applicable": False,
            "implementation_status": "not_started",
            "justification": "由集团统一提供",
        },
        headers=admin_headers,
    )
    assert excluded.status_code == 200, excluded.text
    assert excluded.json()["data"]["applicable"] is False

    summary = client.get(
        f"/api/engagements/{engagement['id']}/soa/summary",
        params={"framework_id": iso["id"]},
        headers=admin_headers,
    ).json()["data"]
    assert summary["applicable"] == 92
    assert summary["excluded"] == 1
    assert summary["excluded_without_justification"] == 0


def test_soa_status_updates_framework_coverage(
    client: TestClient, admin_headers: dict
) -> None:
    engagement, _, _ = _setup(client, admin_headers)
    iso = _frameworks(client, admin_headers)["ISO27001"]
    client.post(
        f"/api/engagements/{engagement['id']}/soa/generate",
        json={"framework_id": iso["id"]},
        headers=admin_headers,
    )
    entries = client.get(
        f"/api/engagements/{engagement['id']}/soa",
        params={"framework_id": iso["id"]},
        headers=admin_headers,
    ).json()["data"]
    by_code = {row["control"]["code"]: row for row in entries}

    done = client.patch(
        f"/api/soa/{by_code['A.8.13']['id']}",
        json={"implementation_status": "implemented", "owner": "运维组"},
        headers=admin_headers,
    )
    assert done.status_code == 200, done.text
    assert done.json()["data"]["owner"] == "运维组"

    summary = client.get(
        f"/api/engagements/{engagement['id']}/soa/summary",
        params={"framework_id": iso["id"]},
        headers=admin_headers,
    ).json()["data"]
    assert summary["implemented"] == 1
    assert summary["not_started"] == 92
    assert summary["coverage_pct"] == 1.1


def test_control_link_and_duplicate_conflict(
    client: TestClient, admin_headers: dict
) -> None:
    _, _, risk = _setup(client, admin_headers)
    iso = _frameworks(client, admin_headers)["ISO27001"]
    control = _control(client, admin_headers, iso["id"], "A.8.13")

    payload = {"control_id": control["id"], "coverage": "full", "notes": "离线备份"}
    created = client.post(
        f"/api/risks/{risk['id']}/controls",
        json=payload,
        headers=admin_headers,
    )
    assert created.status_code == 201, created.text
    assert created.json()["data"]["control"]["code"] == "A.8.13"

    duplicate = client.post(
        f"/api/risks/{risk['id']}/controls",
        json=payload,
        headers=admin_headers,
    )
    assert duplicate.status_code == 409
    assert duplicate.json()["error"]["code"] == "AEG-2002"

    links = client.get(f"/api/risks/{risk['id']}/controls", headers=admin_headers)
    assert len(links.json()["data"]) == 1


def test_coverage_summary_and_unlink(
    client: TestClient, admin_headers: dict
) -> None:
    _, assessment, risk = _setup(client, admin_headers)
    iso = _frameworks(client, admin_headers)["ISO27001"]
    backup = _control(client, admin_headers, iso["id"], "A.8.13")
    network = _control(client, admin_headers, iso["id"], "A.8.22")
    client.post(
        f"/api/risks/{risk['id']}/controls",
        json={"control_id": backup["id"], "coverage": "full"},
        headers=admin_headers,
    )
    client.post(
        f"/api/risks/{risk['id']}/controls",
        json={"control_id": network["id"], "coverage": "partial"},
        headers=admin_headers,
    )

    coverage = client.get(
        f"/api/assessments/{assessment['id']}/coverage", headers=admin_headers
    )
    assert coverage.status_code == 200, coverage.text
    data = coverage.json()["data"]
    assert data["summary"]["total"] == 1
    assert data["summary"]["covered"] == 1
    assert data["summary"]["uncovered"] == 0
    assert data["summary"]["links"] == 2
    assert data["summary"]["coverage_pct"] == 100.0
    assert data["summary"]["by_framework"] == {"ISO27001": 1}
    assert data["summary"]["by_coverage"] == {"full": 1, "partial": 1, "planned": 0}

    first_link = data["rows"][0]["links"][0]
    removed = client.delete(
        f"/api/risk-controls/{first_link['id']}", headers=admin_headers
    )
    assert removed.status_code == 200
    after = client.get(
        f"/api/assessments/{assessment['id']}/coverage", headers=admin_headers
    ).json()["data"]
    assert after["summary"]["links"] == 1


def test_coverage_orders_by_residual_score(
    client: TestClient, admin_headers: dict
) -> None:
    engagement, assessment, first = _setup(client, admin_headers)
    asset = client.post(
        f"/api/engagements/{engagement['id']}/assets",
        json={"name": "备用机房", "category": "facility"},
        headers=admin_headers,
    ).json()["data"]
    threat = client.post(
        f"/api/engagements/{engagement['id']}/threats",
        json={"name": "市电中断", "category": "environmental"},
        headers=admin_headers,
    ).json()["data"]
    link = client.post(
        f"/api/assets/{asset['id']}/threats",
        json={"threat_id": threat["id"], "vulnerability": "无柴发"},
        headers=admin_headers,
    ).json()["data"]
    second = client.post(
        f"/api/assessments/{assessment['id']}/risks",
        json={
            "asset_threat_id": link["id"],
            "likelihood": 5,
            "impact": 5,
            "residual_likelihood": 1,
            "residual_impact": 1,
        },
        headers=admin_headers,
    ).json()["data"]

    assert first["likelihood"] * first["impact"] < second["likelihood"] * second["impact"]
    assert first["residual_score"] > second["residual_score"]

    rows = client.get(
        f"/api/assessments/{assessment['id']}/coverage", headers=admin_headers
    ).json()["data"]["rows"]
    assert [row["risk"]["id"] for row in rows] == [first["id"], second["id"]]


def test_soa_is_scoped_to_one_engagement(
    client: TestClient, admin_headers: dict
) -> None:
    engagement, _, _ = _setup(client, admin_headers)
    other = client.post(
        "/api/engagements",
        json={
            "client_id": client.get("/api/clients").json()["data"][0]["id"],
            "name": "另一个项目",
        },
        headers=admin_headers,
    ).json()["data"]
    iso = _frameworks(client, admin_headers)["ISO27001"]
    client.post(
        f"/api/engagements/{engagement['id']}/soa/generate",
        json={"framework_id": iso["id"]},
        headers=admin_headers,
    )

    summary = client.get(
        f"/api/engagements/{other['id']}/soa/summary",
        params={"framework_id": iso["id"]},
        headers=admin_headers,
    ).json()["data"]
    assert summary["generated"] == 0
    assert summary["applicable"] == 0
    assert summary["coverage_pct"] == 0.0


def test_deleting_risk_removes_links(client: TestClient, admin_headers: dict) -> None:
    _, _, risk = _setup(client, admin_headers)
    iso = _frameworks(client, admin_headers)["ISO27001"]
    control = _control(client, admin_headers, iso["id"], "A.8.13")
    link = client.post(
        f"/api/risks/{risk['id']}/controls",
        json={"control_id": control["id"]},
        headers=admin_headers,
    ).json()["data"]

    assert client.delete(f"/api/risks/{risk['id']}", headers=admin_headers).status_code == 200
    gone = client.delete(f"/api/risk-controls/{link['id']}", headers=admin_headers)
    assert gone.status_code == 404
