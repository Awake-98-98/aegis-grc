"""Risk assessment API: scoring, freezing, appetite and version comparison."""

from __future__ import annotations

from fastapi.testclient import TestClient


def _engagement(client: TestClient, headers: dict, name: str = "风险评估项目") -> dict:
    client.post("/api/clients", json={"name": f"{name}客户"}, headers=headers)
    client_row = client.get("/api/clients").json()["data"][0]
    response = client.post(
        "/api/engagements",
        json={"client_id": client_row["id"], "name": name},
        headers=headers,
    )
    assert response.status_code == 201, response.text
    return response.json()["data"]


def _pair(
    client: TestClient,
    headers: dict,
    engagement_id: str,
    *,
    asset_name: str = "核心数据库",
    threat_name: str = "勒索软件",
) -> dict:
    asset = client.post(
        f"/api/engagements/{engagement_id}/assets",
        json={"name": asset_name, "category": "database"},
        headers=headers,
    ).json()["data"]
    threat = client.post(
        f"/api/engagements/{engagement_id}/threats",
        json={"name": threat_name, "category": "malicious", "actor": "external"},
        headers=headers,
    ).json()["data"]
    link = client.post(
        f"/api/assets/{asset['id']}/threats",
        json={"threat_id": threat["id"], "vulnerability": "备份未离线保存"},
        headers=headers,
    )
    assert link.status_code == 201, link.text
    return link.json()["data"]


def _assessment(client: TestClient, headers: dict, engagement_id: str) -> dict:
    response = client.post(
        f"/api/engagements/{engagement_id}/assessments",
        json={"title": "首轮评估", "assessor": "顾问甲"},
        headers=headers,
    )
    assert response.status_code == 201, response.text
    return response.json()["data"]


def test_assessment_codes_and_default_appetite(
    client: TestClient, admin_headers: dict
) -> None:
    engagement = _engagement(client, admin_headers)
    first = _assessment(client, admin_headers, engagement["id"])
    second = _assessment(client, admin_headers, engagement["id"])
    assert first["code"] == "RA-0001"
    assert second["code"] == "RA-0002"
    assert first["status"] == "draft"

    detail = client.get(f"/api/assessments/{first['id']}", headers=admin_headers)
    assert detail.status_code == 200
    data = detail.json()["data"]
    assert data["item_count"] == 0
    assert data["appetite"]["is_default"] is True
    assert data["appetite"]["max_acceptable_score"] == 9


def test_risk_item_scores_and_audit(client: TestClient, admin_headers: dict) -> None:
    engagement = _engagement(client, admin_headers)
    assessment = _assessment(client, admin_headers, engagement["id"])
    link = _pair(client, admin_headers, engagement["id"])

    response = client.post(
        f"/api/assessments/{assessment['id']}/risks",
        json={
            "asset_threat_id": link["id"],
            "likelihood": 4,
            "impact": 5,
            "residual_likelihood": 2,
            "residual_impact": 3,
            "treatment": "mitigate",
            "rationale": "上线异地备份",
        },
        headers=admin_headers,
    )
    assert response.status_code == 201, response.text
    item = response.json()["data"]
    assert item["inherent_score"] == 20
    assert item["inherent_severity"] == "critical"
    assert item["residual_score"] == 6
    assert item["residual_severity"] == "medium"
    assert item["reduction"] == 14
    assert item["asset_code"] == "AST-0001"
    assert item["within_appetite"] is True

    audit = client.get(
        "/api/audit", params={"action": "risk.create"}, headers=admin_headers
    ).json()["data"]
    assert any(row["entity_id"] == item["id"] for row in audit)


def test_matrix_grade_rejects_out_of_range(
    client: TestClient, admin_headers: dict
) -> None:
    engagement = _engagement(client, admin_headers)
    assessment = _assessment(client, admin_headers, engagement["id"])
    link = _pair(client, admin_headers, engagement["id"])
    response = client.post(
        f"/api/assessments/{assessment['id']}/risks",
        json={"asset_threat_id": link["id"], "likelihood": 6, "impact": 3},
        headers=admin_headers,
    )
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "AEG-2003"


def test_duplicate_pair_is_rejected(client: TestClient, admin_headers: dict) -> None:
    engagement = _engagement(client, admin_headers)
    assessment = _assessment(client, admin_headers, engagement["id"])
    link = _pair(client, admin_headers, engagement["id"])
    payload = {"asset_threat_id": link["id"], "likelihood": 3, "impact": 3}
    assert (
        client.post(
            f"/api/assessments/{assessment['id']}/risks",
            json=payload,
            headers=admin_headers,
        ).status_code
        == 201
    )
    duplicate = client.post(
        f"/api/assessments/{assessment['id']}/risks",
        json=payload,
        headers=admin_headers,
    )
    assert duplicate.status_code == 409
    assert duplicate.json()["error"]["code"] == "AEG-2002"


def test_cross_engagement_pair_is_rejected(
    client: TestClient, admin_headers: dict
) -> None:
    first = _engagement(client, admin_headers, "项目甲")
    second = _engagement(client, admin_headers, "项目乙")
    assessment = _assessment(client, admin_headers, first["id"])
    foreign_link = _pair(client, admin_headers, second["id"])

    response = client.post(
        f"/api/assessments/{assessment['id']}/risks",
        json={"asset_threat_id": foreign_link["id"], "likelihood": 3, "impact": 4},
        headers=admin_headers,
    )
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "AEG-2003"


def test_issue_requires_items_and_freezes_edits(
    client: TestClient, admin_headers: dict
) -> None:
    engagement = _engagement(client, admin_headers)
    assessment = _assessment(client, admin_headers, engagement["id"])
    empty_issue = client.post(
        f"/api/assessments/{assessment['id']}/issue", headers=admin_headers
    )
    assert empty_issue.status_code == 422

    link = _pair(client, admin_headers, engagement["id"])
    item = client.post(
        f"/api/assessments/{assessment['id']}/risks",
        json={"asset_threat_id": link["id"], "likelihood": 3, "impact": 4},
        headers=admin_headers,
    ).json()["data"]

    issued = client.post(
        f"/api/assessments/{assessment['id']}/issue", headers=admin_headers
    )
    assert issued.status_code == 200, issued.text
    assert issued.json()["data"]["status"] == "issued"
    assert issued.json()["data"]["issued_at"]

    edit = client.patch(
        f"/api/risks/{item['id']}",
        json={"likelihood": 5},
        headers=admin_headers,
    )
    assert edit.status_code == 409
    assert edit.json()["error"]["code"] == "AEG-4001"

    delete = client.delete(
        f"/api/assessments/{assessment['id']}", headers=admin_headers
    )
    assert delete.status_code == 409
    assert delete.json()["error"]["code"] == "AEG-4001"

    again = client.post(
        f"/api/assessments/{assessment['id']}/issue", headers=admin_headers
    )
    assert again.status_code == 409


def test_compare_reports_changes(client: TestClient, admin_headers: dict) -> None:
    engagement = _engagement(client, admin_headers)
    baseline = _assessment(client, admin_headers, engagement["id"])
    first_pair = _pair(client, admin_headers, engagement["id"])

    client.post(
        f"/api/assessments/{baseline['id']}/risks",
        json={
            "asset_threat_id": first_pair["id"],
            "likelihood": 4,
            "impact": 4,
            "residual_likelihood": 3,
            "residual_impact": 4,
        },
        headers=admin_headers,
    )
    client.post(f"/api/assessments/{baseline['id']}/issue", headers=admin_headers)

    current = _assessment(client, admin_headers, engagement["id"])
    client.post(
        f"/api/assessments/{current['id']}/risks",
        json={
            "asset_threat_id": first_pair["id"],
            "likelihood": 4,
            "impact": 4,
            "residual_likelihood": 2,
            "residual_impact": 3,
        },
        headers=admin_headers,
    )
    second_pair = _pair(
        client,
        admin_headers,
        engagement["id"],
        asset_name="办公终端",
        threat_name="钓鱼邮件",
    )
    client.post(
        f"/api/assessments/{current['id']}/risks",
        json={"asset_threat_id": second_pair["id"], "likelihood": 3, "impact": 3},
        headers=admin_headers,
    )

    response = client.get(
        f"/api/assessments/{current['id']}/compare/{baseline['id']}",
        headers=admin_headers,
    )
    assert response.status_code == 200, response.text
    data = response.json()["data"]
    assert data["summary"]["changed"] == 1
    assert data["summary"]["added"] == 1
    assert data["summary"]["decreased"] == 1
    changed = next(row for row in data["rows"] if row["change"] == "changed")
    assert changed["before"]["residual_score"] == 12
    assert changed["after"]["residual_score"] == 6
    assert changed["delta_residual"] == -6

    same = client.get(
        f"/api/assessments/{current['id']}/compare/{current['id']}",
        headers=admin_headers,
    )
    assert same.status_code == 422


def test_appetite_threshold_marks_risks(client: TestClient, admin_headers: dict) -> None:
    engagement = _engagement(client, admin_headers)
    assessment = _assessment(client, admin_headers, engagement["id"])
    link = _pair(client, admin_headers, engagement["id"])
    item = client.post(
        f"/api/assessments/{assessment['id']}/risks",
        json={
            "asset_threat_id": link["id"],
            "likelihood": 3,
            "impact": 3,
            "residual_likelihood": 3,
            "residual_impact": 4,
        },
        headers=admin_headers,
    ).json()["data"]

    appetite = client.put(
        f"/api/engagements/{engagement['id']}/risk-appetite",
        json={"max_acceptable_score": 10, "statement": "残余分值不超过 10"},
        headers=admin_headers,
    )
    assert appetite.status_code == 200, appetite.text
    assert appetite.json()["data"]["max_acceptable_score"] == 10

    summary = client.get(
        f"/api/assessments/{assessment['id']}/summary", headers=admin_headers
    ).json()["data"]
    assert summary["total"] == 1
    assert summary["above_appetite"] == 1
    assert summary["by_severity"]["high"] == 1
    assert summary["appetite_threshold"] == 10
    assert summary["average_residual"] == 12.0

    client.put(
        f"/api/engagements/{engagement['id']}/risk-appetite",
        json={"max_acceptable_score": 5, "statement": "收紧到 5"},
        headers=admin_headers,
    )
    edited = client.patch(
        f"/api/risks/{item['id']}",
        json={"rationale": "收紧偏好后复核"},
        headers=admin_headers,
    )
    assert edited.status_code == 200, edited.text
    assert edited.json()["data"]["within_appetite"] is False


def test_delete_draft_assessment_cascades(
    client: TestClient, admin_headers: dict
) -> None:
    engagement = _engagement(client, admin_headers)
    assessment = _assessment(client, admin_headers, engagement["id"])
    link = _pair(client, admin_headers, engagement["id"])
    item = client.post(
        f"/api/assessments/{assessment['id']}/risks",
        json={"asset_threat_id": link["id"], "likelihood": 2, "impact": 2},
        headers=admin_headers,
    ).json()["data"]

    deleted = client.delete(
        f"/api/assessments/{assessment['id']}", headers=admin_headers
    )
    assert deleted.status_code == 200
    assert (
        client.get(f"/api/assessments/{assessment['id']}", headers=admin_headers).status_code
        == 404
    )
    assert client.get(f"/api/risks/{item['id']}", headers=admin_headers).status_code == 404
