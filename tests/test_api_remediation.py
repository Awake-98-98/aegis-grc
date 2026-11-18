"""Remediation task and evidence API."""

from __future__ import annotations

import hashlib
from datetime import date, timedelta

from fastapi.testclient import TestClient


def _engagement(client: TestClient, headers: dict, name: str = "整改项目") -> dict:
    client.post("/api/clients", json={"name": f"{name}客户"}, headers=headers)
    client_row = client.get("/api/clients").json()["data"][0]
    response = client.post(
        "/api/engagements",
        json={"client_id": client_row["id"], "name": name},
        headers=headers,
    )
    assert response.status_code == 201, response.text
    return response.json()["data"]


def _risk(client: TestClient, headers: dict, engagement_id: str) -> dict:
    asset = client.post(
        f"/api/engagements/{engagement_id}/assets",
        json={"name": "核心数据库", "category": "database"},
        headers=headers,
    ).json()["data"]
    threat = client.post(
        f"/api/engagements/{engagement_id}/threats",
        json={"name": "勒索软件", "category": "malicious", "actor": "external"},
        headers=headers,
    ).json()["data"]
    link = client.post(
        f"/api/assets/{asset['id']}/threats",
        json={"threat_id": threat["id"], "vulnerability": "备份未离线保存"},
        headers=headers,
    ).json()["data"]
    assessment = client.post(
        f"/api/engagements/{engagement_id}/assessments",
        json={"title": "整改评估"},
        headers=headers,
    ).json()["data"]
    response = client.post(
        f"/api/assessments/{assessment['id']}/risks",
        json={
            "asset_threat_id": link["id"],
            "likelihood": 4,
            "impact": 5,
            "residual_likelihood": 2,
            "residual_impact": 3,
        },
        headers=headers,
    )
    assert response.status_code == 201, response.text
    return response.json()["data"]


def _task(client: TestClient, headers: dict, engagement_id: str, **payload) -> dict:
    body = {"title": "完成离线备份"}
    body.update(payload)
    response = client.post(
        f"/api/engagements/{engagement_id}/remediation-tasks",
        json=body,
        headers=headers,
    )
    assert response.status_code == 201, response.text
    return response.json()["data"]


def _member(client: TestClient, admin: dict, email: str, role: str) -> dict:
    response = client.post(
        "/api/users",
        headers={"X-CSRF-Token": admin["csrf_token"]},
        json={
            "email": email,
            "display_name": role,
            "password": "MemberPass123",
            "role": role,
        },
    )
    assert response.status_code == 201, response.text
    login = client.post(
        "/api/auth/login", json={"email": email, "password": "MemberPass123"}
    )
    return {"Authorization": f"Bearer {login.json()['data']['token']}"}


def test_task_codes_and_risk_snapshot(
    client: TestClient, admin_headers: dict
) -> None:
    engagement = _engagement(client, admin_headers)
    risk = _risk(client, admin_headers, engagement["id"])

    first = client.post(
        f"/api/risks/{risk['id']}/remediation",
        json={"priority": "high", "owner": "运维组"},
        headers=admin_headers,
    )
    assert first.status_code == 201, first.text
    task = first.json()["data"]
    assert task["code"] == "RT-0001"
    assert task["status"] == "open"
    assert task["risk_item_id"] == risk["id"]
    assert "AST-0001" in task["risk_snapshot"]
    assert "THR-0001" in task["risk_snapshot"]
    assert "残余 6" in task["risk_snapshot"]

    second = _task(client, admin_headers, engagement["id"], title="复核备份策略")
    assert second["code"] == "RT-0002"


def test_tasks_are_scoped_to_their_engagement(
    client: TestClient, admin_headers: dict
) -> None:
    first = _engagement(client, admin_headers, "项目甲")
    second = _engagement(client, admin_headers, "项目乙")
    task = _task(client, admin_headers, first["id"])

    listing = client.get(
        f"/api/engagements/{second['id']}/remediation-tasks", headers=admin_headers
    )
    assert listing.status_code == 200
    assert listing.json()["meta"]["total"] == 0

    summary = client.get(
        f"/api/engagements/{second['id']}/remediation/summary", headers=admin_headers
    ).json()["data"]
    assert summary["total"] == 0
    assert task["engagement_id"] == first["id"]


def test_transition_rules_and_completion_time(
    client: TestClient, admin_headers: dict
) -> None:
    engagement = _engagement(client, admin_headers)
    task = _task(client, admin_headers, engagement["id"])

    skipped = client.post(
        f"/api/remediation-tasks/{task['id']}/transition",
        json={"status": "done"},
        headers=admin_headers,
    )
    assert skipped.status_code == 409
    assert skipped.json()["error"]["code"] == "AEG-4001"

    started = client.post(
        f"/api/remediation-tasks/{task['id']}/transition",
        json={"status": "in_progress", "note": "开始实施"},
        headers=admin_headers,
    )
    assert started.status_code == 200, started.text
    assert started.json()["data"]["status"] == "in_progress"

    done = client.post(
        f"/api/remediation-tasks/{task['id']}/transition",
        json={"status": "done"},
        headers=admin_headers,
    )
    assert done.status_code == 200, done.text
    assert done.json()["data"]["status"] == "done"
    assert done.json()["data"]["completed_at"]

    reopen = client.post(
        f"/api/remediation-tasks/{task['id']}/transition",
        json={"status": "in_progress"},
        headers=admin_headers,
    )
    assert reopen.status_code == 409


def test_overdue_filter_and_summary(
    client: TestClient, admin_headers: dict
) -> None:
    engagement = _engagement(client, admin_headers)
    late = _task(
        client,
        admin_headers,
        engagement["id"],
        title="逾期任务",
        due_date=(date.today() - timedelta(days=2)).isoformat(),
    )
    client.post(
        f"/api/remediation-tasks/{late['id']}/transition",
        json={"status": "in_progress"},
        headers=admin_headers,
    )
    _task(
        client,
        admin_headers,
        engagement["id"],
        title="未来任务",
        due_date=(date.today() + timedelta(days=10)).isoformat(),
    )

    overdue = client.get(
        f"/api/engagements/{engagement['id']}/remediation-tasks",
        params={"overdue": "true"},
        headers=admin_headers,
    )
    assert overdue.status_code == 200
    assert overdue.json()["meta"]["total"] == 1
    assert overdue.json()["data"][0]["code"] == "RT-0001"
    assert overdue.json()["data"][0]["is_overdue"] is True

    summary = client.get(
        f"/api/engagements/{engagement['id']}/remediation/summary",
        headers=admin_headers,
    ).json()["data"]
    assert summary["total"] == 2
    assert summary["overdue"] == 1
    assert summary["due_soon"] == 0


def test_evidence_is_idempotent_by_digest(
    client: TestClient, admin_headers: dict, settings
) -> None:
    engagement = _engagement(client, admin_headers)
    task = _task(client, admin_headers, engagement["id"])
    payload = b"backup restore drill record"

    first = client.post(
        f"/api/remediation-tasks/{task['id']}/evidence",
        files={"file": ("drill.txt", payload, "text/plain")},
        headers=admin_headers,
    )
    assert first.status_code == 201, first.text
    row = first.json()["data"]
    assert row["created"] is True
    assert row["sha256"] == hashlib.sha256(payload).hexdigest()
    assert row["size_bytes"] == len(payload)

    second = client.post(
        f"/api/remediation-tasks/{task['id']}/evidence",
        files={"file": ("drill-copy.txt", payload, "text/plain")},
        headers=admin_headers,
    )
    assert second.status_code == 201, second.text
    assert second.json()["data"]["created"] is False
    assert second.json()["data"]["id"] == row["id"]

    listing = client.get(
        f"/api/remediation-tasks/{task['id']}/evidence", headers=admin_headers
    ).json()
    assert listing["meta"]["total"] == 1

    digest = row["sha256"]
    stored = settings.evidence_path / digest[:2] / digest
    assert stored.read_bytes() == payload


def test_evidence_rejects_empty_and_oversized_files(
    client: TestClient, admin_headers: dict
) -> None:
    engagement = _engagement(client, admin_headers)
    task = _task(client, admin_headers, engagement["id"])

    empty = client.post(
        f"/api/remediation-tasks/{task['id']}/evidence",
        files={"file": ("empty.txt", b"", "text/plain")},
        headers=admin_headers,
    )
    assert empty.status_code == 422
    assert empty.json()["error"]["code"] == "AEG-2003"

    oversized = client.post(
        f"/api/remediation-tasks/{task['id']}/evidence",
        files={"file": ("big.bin", b"x" * (10 * 1024 * 1024 + 1), "application/octet-stream")},
        headers=admin_headers,
    )
    assert oversized.status_code == 422


def test_evidence_download_and_delete_removes_blob(
    client: TestClient, admin_headers: dict, settings
) -> None:
    engagement = _engagement(client, admin_headers)
    task = _task(client, admin_headers, engagement["id"])
    payload = "证据正文".encode("utf-8")
    row = client.post(
        f"/api/remediation-tasks/{task['id']}/evidence",
        files={"file": ("证据.txt", payload, "text/plain")},
        headers=admin_headers,
    ).json()["data"]

    download = client.get(f"/api/evidence/{row['id']}/download", headers=admin_headers)
    assert download.status_code == 200
    assert download.content == payload
    assert "attachment" in download.headers["content-disposition"]

    deleted = client.delete(f"/api/evidence/{row['id']}", headers=admin_headers)
    assert deleted.status_code == 200
    assert not (settings.evidence_path / row["sha256"][:2] / row["sha256"]).exists()
    assert client.get(
        f"/api/remediation-tasks/{task['id']}/evidence", headers=admin_headers
    ).json()["meta"]["total"] == 0


def test_viewer_reads_but_cannot_change_tasks(
    client: TestClient, bootstrap_admin: dict, admin_headers: dict
) -> None:
    engagement = _engagement(client, admin_headers)
    task = _task(client, admin_headers, engagement["id"])
    viewer = _member(client, bootstrap_admin, "viewer-rem@aegis.test", "viewer")

    assert client.get(
        f"/api/engagements/{engagement['id']}/remediation-tasks", headers=viewer
    ).status_code == 200
    assert client.get(
        f"/api/remediation-tasks/{task['id']}", headers=viewer
    ).status_code == 200
    assert client.get(
        f"/api/remediation-tasks/{task['id']}/evidence", headers=viewer
    ).status_code == 200

    denied = client.post(
        f"/api/engagements/{engagement['id']}/remediation-tasks",
        json={"title": "越权任务"},
        headers=viewer,
    )
    assert denied.status_code == 403
    assert denied.json()["error"]["code"] == "AEG-3002"
    assert client.post(
        f"/api/remediation-tasks/{task['id']}/transition",
        json={"status": "in_progress"},
        headers=viewer,
    ).status_code == 403
