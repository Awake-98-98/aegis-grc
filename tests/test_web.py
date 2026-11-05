"""Server-rendered console pages and CSRF protection."""

from __future__ import annotations

from fastapi.testclient import TestClient


def test_dashboard_requires_login(client: TestClient) -> None:
    response = client.get("/")
    assert response.status_code == 303
    assert response.headers["location"].endswith("/login")


def test_setup_page_and_submit(client: TestClient) -> None:
    assert client.get("/setup").status_code == 200
    response = client.post(
        "/setup",
        data={
            "email": "webadmin@aegis.test",
            "display_name": "Web Admin",
            "password": "WebAdminPass123",
        },
    )
    assert response.status_code == 303
    assert response.headers["location"] == "/"
    dashboard = client.get("/")
    assert dashboard.status_code == 200
    assert "咨询工作台" in dashboard.text


def test_setup_is_not_available_twice(client: TestClient, bootstrap_admin: dict) -> None:
    response = client.get("/setup")
    assert response.status_code == 303
    assert response.headers["location"] == "/"


def test_dashboard_renders_counts(client: TestClient, bootstrap_admin: dict) -> None:
    dashboard = client.get("/")
    assert dashboard.status_code == 200
    assert "客户总数" in dashboard.text
    assert bootstrap_admin["user"]["email"] in client.get("/account").text


def test_client_pages(client: TestClient, bootstrap_admin: dict) -> None:
    csrf = bootstrap_admin["csrf_token"]
    assert client.get("/clients/new").status_code == 200

    created = client.post(
        "/clients",
        data={
            "csrf_token": csrf,
            "name": "网页客户",
            "industry": "能源",
            "contact_name": "赵六",
            "contact_email": "zhao@energy.example",
            "status": "active",
            "notes": "来自网页表单",
        },
    )
    assert created.status_code == 303
    detail_url = created.headers["location"]
    detail = client.get(detail_url)
    assert detail.status_code == 200
    assert "网页客户" in detail.text
    assert "客户变更轨迹" in detail.text

    listing = client.get("/clients")
    assert listing.status_code == 200
    assert "网页客户" in listing.text


def test_web_form_requires_csrf(client: TestClient, bootstrap_admin: dict) -> None:
    response = client.post("/clients", data={"name": "无令牌请求"})
    assert response.status_code == 403
    assert "AEG-3003" in response.text


def test_engagement_web_flow(client: TestClient, bootstrap_admin: dict) -> None:
    csrf = bootstrap_admin["csrf_token"]
    client.post(
        "/clients",
        data={"csrf_token": csrf, "name": "网页项目客户"},
    )
    clients_page = client.get("/clients").text
    assert "网页项目客户" in clients_page
    # The new engagement form is reachable and lists the client.
    form = client.get("/engagements/new")
    assert form.status_code == 200
    assert "选择客户" in form.text


def test_admin_page_and_member_creation(client: TestClient, bootstrap_admin: dict) -> None:
    csrf = bootstrap_admin["csrf_token"]
    assert client.get("/users").status_code == 200
    created = client.post(
        "/users",
        data={
            "csrf_token": csrf,
            "email": "newmember@aegis.test",
            "display_name": "新成员",
            "password": "MemberPass123",
            "role": "viewer",
        },
    )
    assert created.status_code == 303
    listing = client.get("/users")
    assert "newmember@aegis.test" in listing.text


def test_viewer_cannot_open_admin_page(client: TestClient, bootstrap_admin: dict) -> None:
    csrf = bootstrap_admin["csrf_token"]
    client.post(
        "/api/users",
        headers={"X-CSRF-Token": csrf},
        json={
            "email": "viewer@aegis.test",
            "display_name": "Viewer",
            "password": "ViewerPass123",
            "role": "viewer",
        },
    )
    client.post("/logout", data={"csrf_token": csrf})
    login = client.post(
        "/login", data={"email": "viewer@aegis.test", "password": "ViewerPass123"}
    )
    assert login.status_code == 303
    assert client.get("/users").status_code == 403


def test_unknown_page_returns_error_page(client: TestClient, bootstrap_admin: dict) -> None:
    response = client.get("/engagements/not-found")
    assert response.status_code == 404
    assert "请求未完成" in response.text
