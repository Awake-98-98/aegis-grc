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


def test_assets_import_and_export(tmp_path: Path, capsys) -> None:
    home = str(tmp_path)
    main(["--home", home, "init"])
    main(["--home", home, "seed-demo"])
    capsys.readouterr()

    csv_path = tmp_path / "extra.csv"
    csv_path.write_text(
        "name,category,confidentiality,integrity,availability\n"
        "CLI 导入资产,server,3,3,3\n",
        encoding="utf-8",
    )
    assert (
        main(
            [
                "--home",
                home,
                "assets",
                "import",
                "--engagement",
                "ENG-2026-0001",
                "--file",
                str(csv_path),
            ]
        )
        == 0
    )
    output = capsys.readouterr().out
    assert "imported 1" in output

    export_path = tmp_path / "assets.csv"
    assert (
        main(
            [
                "--home",
                home,
                "assets",
                "export",
                "--engagement",
                "ENG-2026-0001",
                "--out",
                str(export_path),
            ]
        )
        == 0
    )
    exported = export_path.read_text(encoding="utf-8")
    assert "CLI 导入资产" in exported
    assert "AST-0006" in exported


def test_assets_import_unknown_engagement(tmp_path: Path, capsys) -> None:
    home = str(tmp_path)
    main(["--home", home, "init"])
    main(["--home", home, "seed-demo"])
    csv_path = tmp_path / "extra.csv"
    csv_path.write_text("name\n资产\n", encoding="utf-8")
    assert (
        main(
            [
                "--home",
                home,
                "assets",
                "import",
                "--engagement",
                "ENG-9999-9999",
                "--file",
                str(csv_path),
            ]
        )
        == 2
    )
    assert "engagement not found" in capsys.readouterr().err


def test_assets_template(tmp_path: Path, capsys) -> None:
    home = str(tmp_path)
    out_path = tmp_path / "template.csv"
    assert main(["--home", home, "assets", "template", "--out", str(out_path)]) == 0
    assert out_path.read_text(encoding="utf-8").lstrip("\ufeff").startswith(
        "name,asset_type,category"
    )


def test_risks_list_and_export(tmp_path: Path, capsys) -> None:
    home = str(tmp_path)
    main(["--home", home, "init"])
    main(["--home", home, "seed-demo"])
    capsys.readouterr()

    assert (
        main(["--home", home, "risks", "list", "--engagement", "ENG-2026-0001"]) == 0
    )
    listing = capsys.readouterr().out
    assert "RA-0001" in listing
    assert "RA-0002" in listing
    assert "issued" in listing

    out_path = tmp_path / "register.csv"
    assert (
        main(
            [
                "--home",
                home,
                "risks",
                "export",
                "--engagement",
                "ENG-2026-0001",
                "--assessment",
                "RA-0001",
                "--out",
                str(out_path),
            ]
        )
        == 0
    )
    exported = out_path.read_text(encoding="utf-8").lstrip("\ufeff")
    assert exported.startswith("asset_code,asset_name,threat_code")
    assert "AST-0001" in exported
    assert "mitigate" in exported


def test_risks_export_unknown_assessment(tmp_path: Path, capsys) -> None:
    home = str(tmp_path)
    main(["--home", home, "init"])
    main(["--home", home, "seed-demo"])
    assert (
        main(
            [
                "--home",
                home,
                "risks",
                "export",
                "--engagement",
                "ENG-2026-0001",
                "--assessment",
                "RA-9999",
            ]
        )
        == 2
    )
    assert "assessment not found" in capsys.readouterr().err
