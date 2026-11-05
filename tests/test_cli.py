"""CLI smoke tests against a real SQLite file."""

from __future__ import annotations

from pathlib import Path

from aegis.cli import main


def test_init_status_and_admin(tmp_path: Path, capsys) -> None:
    home = str(tmp_path)
    assert main(["--home", home, "init"]) == 0
    assert (tmp_path / "aegis.sqlite3").exists()

    assert (
        main(
            [
                "--home",
                home,
                "create-admin",
                "--email",
                "cli@aegis.test",
                "--display-name",
                "CLI Admin",
                "--password",
                "CliAdminPass123",
            ]
        )
        == 0
    )
    captured = capsys.readouterr()
    assert "CLI Admin" in captured.out or "cli@aegis.test" in captured.out

    assert main(["--home", home, "status"]) == 0
    status_out = capsys.readouterr().out
    assert "schema:" in status_out
    assert "users:" in status_out


def test_seed_demo_is_idempotent(tmp_path: Path, capsys) -> None:
    home = str(tmp_path)
    main(["--home", home, "init"])
    assert main(["--home", home, "seed-demo"]) == 0
    assert main(["--home", home, "seed-demo"]) == 0
    output = capsys.readouterr().out
    assert "demo data loaded" in output
    assert "already present" in output


def test_create_user_requires_admin(tmp_path: Path, capsys) -> None:
    home = str(tmp_path)
    main(["--home", home, "init"])
    assert (
        main(
            [
                "--home",
                home,
                "create-user",
                "--email",
                "member@aegis.test",
                "--display-name",
                "Member",
                "--password",
                "MemberPass123",
            ]
        )
        == 2
    )
