"""Remediation and evidence console pages."""

from __future__ import annotations

from fastapi.testclient import TestClient


def _engagement(client: TestClient, headers: dict) -> dict:
    client.post("/api/clients", json={"name": "整改页面客户"}, headers=headers)
    client_row = client.get("/api/clients").json()["data"][0]
    response = client.post(
        "/api/engagements",
        json={"client_id": client_row["id"], "name": "整改页面项目"},
        headers=headers,
    )
    assert response.status_code == 201, response.text
    return response.json()["data"]


def _risk(client: TestClient, headers: dict, engagement_id: str) -> dict:
    asset = client.post(
        f"/api/engagements/{engagement_id}/assets",
        json={"name": "文件服务器"},
        headers=headers,
    ).json()["data"]
    threat = client.post(
        f"/api/engagements/{engagement_id}/threats",
        json={"name": "勒索软件"},
        headers=headers,
    ).json()["data"]
    link = client.post(
        f"/api/assets/{asset['id']}/threats",
        json={"threat_id": threat["id"], "vulnerability": "备份未离线"},
        headers=headers,
    ).json()["data"]
    assessment = client.post(
        f"/api/engagements/{engagement_id}/assessments",
        json={"title": "页面评估"},
        headers=headers,
    ).json()["data"]
    response = client.post(
        f"/api/assessments/{assessment['id']}/risks",
        json={"asset_threat_id": link["id"], "likelihood": 3, "impact": 4},
        headers=headers,
    )
    assert response.status_code == 201, response.text
    return {"assessment": assessment, "risk": response.json()["data"]}


def _task(client: TestClient, headers: dict, engagement_id: str) -> dict:
    response = client.post(
        f"/api/engagements/{engagement_id}/remediation-tasks",
        json={"title": "完成离线备份演练"},
        headers=headers,
    )
    assert response.status_code == 201, response.text
    return response.json()["data"]


def test_list_create_and_detail_pages(
    client: TestClient, admin_headers: dict, bootstrap_admin: dict
) -> None:
    engagement = _engagement(client, admin_headers)
    scoped = client.get(f"/engagements/{engagement['id']}/remediation")
    assert scoped.status_code == 200
    assert "新建整改任务" in scoped.text

    created = client.post(
        f"/engagements/{engagement['id']}/remediation",
        data={
            "csrf_token": bootstrap_admin["csrf_token"],
            "title": "完成离线备份演练",
            "description": "每季度从离线副本恢复一次核心库",
            "priority": "high",
            "owner": "运维组",
            "due_date": "2026-12-31",
            "notes": "",
        },
    )
    assert created.status_code == 303
    location = created.headers["location"]
    detail = client.get(location)
    assert detail.status_code == 200
    assert "完成离线备份演练" in detail.text
    assert "运维组" in detail.text

    global_page = client.get("/remediation")
    assert global_page.status_code == 200
    assert engagement["code"] in global_page.text
    assert "完成离线备份演练" in global_page.text

    tasks = client.get(
        f"/api/engagements/{engagement['id']}/remediation-tasks", headers=admin_headers
    ).json()["data"]
    assert tasks[0]["code"] == "RT-0001"


def test_transition_and_evidence_flow(
    client: TestClient, admin_headers: dict, bootstrap_admin: dict
) -> None:
    csrf = bootstrap_admin["csrf_token"]
    engagement = _engagement(client, admin_headers)
    task = _task(client, admin_headers, engagement["id"])

    started = client.post(
        f"/remediation/{task['id']}/transition",
        data={"csrf_token": csrf, "status": "in_progress", "note": "进入实施"},
    )
    assert started.status_code == 303
    assert "进行中" in client.get(f"/remediation/{task['id']}").text

    uploaded = client.post(
        f"/remediation/{task['id']}/evidence",
        data={"csrf_token": csrf},
        files={"file": ("backup-plan.txt", b"offsite copy every day", "text/plain")},
    )
    assert uploaded.status_code == 303
    detail = client.get(f"/remediation/{task['id']}")
    assert "backup-plan.txt" in detail.text

    rows = client.get(
        f"/api/remediation-tasks/{task['id']}/evidence", headers=admin_headers
    ).json()["data"]
    download = client.get(f"/evidence/{rows[0]['id']}/download")
    assert download.status_code == 200
    assert download.content == b"offsite copy every day"

    removed = client.post(
        f"/evidence/{rows[0]['id']}/delete", data={"csrf_token": csrf}
    )
    assert removed.status_code == 303
    assert "backup-plan.txt" not in client.get(f"/remediation/{task['id']}").text


def test_risk_row_creates_remediation_task(
    client: TestClient, admin_headers: dict, bootstrap_admin: dict
) -> None:
    engagement = _engagement(client, admin_headers)
    rows = _risk(client, admin_headers, engagement["id"])
    page = client.get(f"/assessments/{rows['assessment']['id']}")
    assert page.status_code == 200
    assert f"/risks/{rows['risk']['id']}/remediation" in page.text

    created = client.post(
        f"/risks/{rows['risk']['id']}/remediation",
        data={"csrf_token": bootstrap_admin["csrf_token"], "owner": "安全组"},
    )
    assert created.status_code == 303
    tasks = client.get(
        f"/api/engagements/{engagement['id']}/remediation-tasks", headers=admin_headers
    ).json()["data"]
    assert len(tasks) == 1
    assert tasks[0]["owner"] == "安全组"
    assert "AST-0001" in tasks[0]["risk_snapshot"]


def test_viewer_sees_read_only_remediation(
    client: TestClient, admin_headers: dict, bootstrap_admin: dict
) -> None:
    engagement = _engagement(client, admin_headers)
    task = _task(client, admin_headers, engagement["id"])
    client.post(
        "/api/users",
        headers=admin_headers,
        json={
            "email": "viewer-rem-web@aegis.test",
            "display_name": "只读用户",
            "password": "MemberPass123",
            "role": "viewer",
        },
    )
    login = client.post(
        "/api/auth/login",
        json={"email": "viewer-rem-web@aegis.test", "password": "MemberPass123"},
    )
    assert login.status_code == 200, login.text
    csrf = login.json()["data"]["csrf_token"]

    assert client.get("/remediation").status_code == 200
    scoped = client.get(f"/engagements/{engagement['id']}/remediation")
    assert scoped.status_code == 200
    assert "新建整改任务" not in scoped.text

    detail = client.get(f"/remediation/{task['id']}")
    assert detail.status_code == 200
    assert f"/remediation/{task['id']}/transition" not in detail.text
    assert f"/remediation/{task['id']}/evidence" not in detail.text
    assert f"/remediation/{task['id']}/edit" not in detail.text

    denied = client.post(
        f"/engagements/{engagement['id']}/remediation",
        data={"csrf_token": csrf, "title": "只读用户不应创建"},
    )
    assert denied.status_code == 403
