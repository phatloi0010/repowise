"""Doctor's ``index-data`` check for stale analyzer/history stamps and empty git tables."""

from __future__ import annotations

import asyncio
import json
import subprocess
from pathlib import Path
from typing import Any

from repowise.cli.commands.doctor_cmd import DoctorCheck
from repowise.cli.commands.doctor_cmd._checks.context import CheckContext
from repowise.cli.commands.doctor_cmd._checks.stores import _index_data_row, store_checks
from repowise.core.analysis.health import HEALTH_ANALYZER_VERSION
from repowise.core.analysis.security_scan import SECURITY_SCANNER_VERSION
from repowise.core.ingestion.git_indexer import GIT_HISTORY_VERSION, GIT_HISTORY_VERSION_KEY
from repowise.core.ingestion.git_indexer._constants import GIT_HISTORY_BACKFILL_REWALK

FIX_COMMAND = "repowise update --index-only"


def _current_stamps(**overrides: Any) -> dict[str, Any]:
    return {
        "last_sync_commit": "adbc881300000000000000000000000000000000",
        GIT_HISTORY_VERSION_KEY: GIT_HISTORY_VERSION,
        "health_analyzer_version": HEALTH_ANALYZER_VERSION,
        "security_scanner_version": SECURITY_SCANNER_VERSION,
        **overrides,
    }


async def _build_repo(
    tmp_path: Path,
    state: dict[str, Any],
    *,
    seed_git: bool = False,
    seed_blame: bool = False,
) -> Path:
    from repowise.core.persistence import create_engine, create_session_factory, get_session
    from repowise.core.persistence.crud import (
        upsert_git_commit_files_bulk,
        upsert_git_commits_bulk,
        upsert_git_function_blame_bulk,
        upsert_git_metadata_bulk,
        upsert_repository,
    )
    from repowise.core.persistence.database import init_db

    repo_path = (tmp_path / "repo").resolve()
    repo_path.mkdir(parents=True, exist_ok=True)
    subprocess.run(["git", "init", "-q"], cwd=str(repo_path), check=True)
    rw = repo_path / ".repowise"
    rw.mkdir(exist_ok=True)
    (rw / "state.json").write_text(json.dumps(state), encoding="utf-8")

    engine = create_engine(f"sqlite+aiosqlite:///{rw / 'wiki.db'}")
    await init_db(engine)
    sf = create_session_factory(engine)
    async with get_session(sf) as session:
        repo = await upsert_repository(
            session, name="repo", local_path=str(repo_path), url="https://example.test/repo"
        )
        if seed_git:
            await upsert_git_metadata_bulk(
                session,
                repo.id,
                [{"file_path": "a.py", "commit_count_total": 1}],
            )
            await upsert_git_commits_bulk(
                session,
                repo.id,
                [{"sha": "a" * 40, "author_name": "Dev", "author_email": "d@e.test"}],
            )
            await upsert_git_commit_files_bulk(
                session,
                repo.id,
                [{"sha": "a" * 40, "file_path": "a.py", "lines_added": 5, "lines_deleted": 1}],
            )
        if seed_blame:
            await upsert_git_function_blame_bulk(
                session,
                repo.id,
                [
                    {
                        "symbol_id": "a.py::fn",
                        "file_path": "a.py",
                        "function_name": "fn",
                        "start_line": 1,
                        "end_line": 4,
                        "line_count": 4,
                        "mod_count": 1,
                    }
                ],
            )
        await session.commit()
    await engine.dispose()
    return repo_path


def _check_row(repo_path: Path, *, quick: bool = True) -> DoctorCheck:
    state = json.loads((repo_path / ".repowise" / "state.json").read_text(encoding="utf-8"))
    ctx = CheckContext(
        repo_path=repo_path,
        repowise_dir=repo_path / ".repowise",
        quick=quick,
        db_ok=True,
        state=state,
        state_ok=True,
    )
    rows = [r for r in store_checks(ctx) if r.id == "index-data"]
    assert len(rows) == 1
    return rows[0]


def test_current_stamps_pass_as_ok(tmp_path: Path) -> None:
    repo = asyncio.run(
        _build_repo(
            tmp_path,
            _current_stamps(git_tier="full"),
            seed_git=True,
            seed_blame=True,
        )
    )
    row = _check_row(repo)
    assert (row.id, row.name, row.ok, row.level, row.fix) == (
        "index-data",
        "Index data",
        True,
        "ok",
        None,
    )
    assert row.detail == "Current"


def test_stale_history_stamp_warns_with_fix(tmp_path: Path) -> None:
    repo = asyncio.run(
        _build_repo(
            tmp_path,
            _current_stamps(**{GIT_HISTORY_VERSION_KEY: GIT_HISTORY_VERSION - 1}),
        )
    )
    row = _check_row(repo)
    assert (row.id, row.ok, row.level, row.fix) == (
        "index-data",
        True,
        "warn",
        FIX_COMMAND,
    )
    assert "git history" in row.detail
    assert FIX_COMMAND in row.detail


def test_attribution_backfill_history_stamp_warns_with_fix(tmp_path: Path) -> None:
    repo = asyncio.run(
        _build_repo(
            tmp_path,
            _current_stamps(**{GIT_HISTORY_VERSION_KEY: GIT_HISTORY_BACKFILL_REWALK}),
        )
    )
    row = _check_row(repo)
    assert (row.level, row.fix) == ("warn", FIX_COMMAND)
    assert "attribution backfill" in row.detail


def test_stale_health_and_security_stamps_are_named(tmp_path: Path) -> None:
    repo = asyncio.run(
        _build_repo(
            tmp_path,
            _current_stamps(
                health_analyzer_version=HEALTH_ANALYZER_VERSION - 1,
                security_scanner_version=SECURITY_SCANNER_VERSION - 1,
            ),
        )
    )
    row = _check_row(repo)
    assert (row.ok, row.level, row.fix) == (True, "warn", FIX_COMMAND)
    assert "health" in row.detail
    assert "security" in row.detail


def test_empty_git_tables_at_full_tier_warns(tmp_path: Path) -> None:
    repo = asyncio.run(
        _build_repo(
            tmp_path,
            _current_stamps(git_tier="full"),
            seed_git=False,
            seed_blame=False,
        )
    )
    row = _check_row(repo)
    assert (row.id, row.ok, row.level, row.fix) == (
        "index-data",
        True,
        "warn",
        FIX_COMMAND,
    )
    for table in ("git_metadata", "git_commits", "git_commit_files", "git_function_blame"):
        assert table in row.detail


def test_empty_function_blame_at_essential_tier_is_ok(tmp_path: Path) -> None:
    repo = asyncio.run(
        _build_repo(
            tmp_path,
            _current_stamps(git_tier="essential"),
            seed_git=True,
            seed_blame=False,
        )
    )
    row = _check_row(repo)
    assert (row.level, row.fix, row.detail) == ("ok", None, "Current")


def test_direct_row_helper_loads_state_when_context_state_is_empty(tmp_path: Path) -> None:
    repo = asyncio.run(_build_repo(tmp_path, _current_stamps()))
    ctx = CheckContext(repo_path=repo, repowise_dir=repo / ".repowise")
    row = _index_data_row(ctx)
    assert (row.id, row.level, row.detail) == ("index-data", "ok", "Current")
