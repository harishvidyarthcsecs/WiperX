"""Tests for regular-file erasure utilities."""

import pytest

from core.eraser_file.batch import shred_paths
from core.eraser_file.file_shredder import shred_file


def test_single_file_is_erased_with_correct_result(tmp_path):
    """A regular file is overwritten, removed, and reported accurately."""
    target = tmp_path / "secret.txt"
    target.write_bytes(b"secret")

    result = shred_file(str(target), passes=1, rename_rounds=1)

    assert result.ok is True
    assert result.path == str(target)
    assert result.size_bytes == 6
    assert result.passes == 1
    assert result.renames == 1
    assert result.method == "random+zero"
    assert result.error is None
    assert result.duration_s >= 0
    assert not target.exists()


def test_large_file_is_erased(tmp_path):
    """A five-megabyte file is processed in multiple chunks."""
    target = tmp_path / "large.bin"
    target.write_bytes(b"x" * (5 * 1024 * 1024))

    result = shred_file(str(target), chunk_size=1024 * 1024)

    assert result.ok is True
    assert result.size_bytes == 5 * 1024 * 1024
    assert not target.exists()


def test_zero_rename_rounds_leaves_no_file(tmp_path):
    """Removal succeeds when rename obfuscation is disabled."""
    target = tmp_path / "no-rename.txt"
    target.write_text("data")

    result = shred_file(str(target), rename_rounds=0)

    assert result.ok is True
    assert result.renames == 0
    assert not target.exists()


def test_nested_directory_tree_is_fully_removed(tmp_path):
    """Recursive processing removes files and now-empty directory parents."""
    nested = tmp_path / "root" / "one" / "two"
    nested.mkdir(parents=True)
    (nested / "a.txt").write_text("a")
    (nested.parent / "b.txt").write_text("b")

    summary = shred_paths([str(tmp_path / "root")])

    assert summary.succeeded == 2
    assert summary.failed == 0
    assert not (tmp_path / "root").exists()


def test_non_recursive_directory_is_skipped(tmp_path):
    """A directory remains intact when recursive expansion is disabled."""
    directory = tmp_path / "keep"
    directory.mkdir()
    (directory / "file.txt").write_text("data")

    summary = shred_paths([str(directory)], recursive=False)

    assert summary.total == 1
    assert summary.failed == 1
    assert summary.results[0].error == "directory skipped (non-recursive)"
    assert directory.exists()


def test_symlink_is_not_followed(tmp_path):
    """A symlink result fails without changing its target."""
    target = tmp_path / "target.txt"
    link = tmp_path / "link.txt"
    target.write_text("keep")
    try:
        link.symlink_to(target)
    except OSError as error:
        pytest.skip(f"symlinks unavailable: {error}")

    result = shred_file(str(link))

    assert result.ok is False
    assert result.error == "symlink skipped"
    assert target.read_text() == "keep"
    assert link.is_symlink()


def test_permission_error_returns_result_not_exception(tmp_path, monkeypatch):
    """Expected permission failures are captured in the result."""
    target = tmp_path / "protected.txt"
    target.write_text("protected")

    def raise_permission_error(*args, **kwargs):
        raise PermissionError("permission denied")

    monkeypatch.setattr("builtins.open", raise_permission_error)
    result = shred_file(str(target))

    assert result.ok is False
    assert "permission denied" in (result.error or "")
    assert target.exists()


def test_progress_count_and_sorted_results(tmp_path):
    """Progress fires once per result and final results use path order."""
    first = tmp_path / "zeta.txt"
    second = tmp_path / "alpha.txt"
    first.write_text("z")
    second.write_text("a")
    progress = []

    summary = shred_paths(
        [str(first), str(second)], workers=2, on_progress=progress.append
    )

    assert len(progress) == summary.total == 2
    assert [result.path for result in summary.results] == sorted(
        result.path for result in summary.results
    )
    assert summary.bytes_erased == 2
