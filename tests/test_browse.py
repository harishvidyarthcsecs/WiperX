"""Tests for the /browse location-picker endpoint (Part C).

Covers: listing shape, dirs-first ordering, navigation + parent, the `..`
rejection, sandbox-root confinement, and the wipe-permission gate.
"""

from pathlib import Path


def _sandbox(app):
    return Path(app.config["FSROOT_SANDBOX"])


def test_browse_list_root_shape(admin, app):
    box = _sandbox(app)
    (box / "sub").mkdir(exist_ok=True)
    (box / "a.txt").write_text("hello")

    resp = admin.get("/browse/list")
    assert resp.status_code == 200
    data = resp.get_json()

    assert set(data) == {"root", "cwd", "parent", "entries"}
    assert data["cwd"] == data["root"]
    assert data["parent"] is None

    by_name = {e["name"]: e for e in data["entries"]}
    assert set(by_name["sub"]) == {"name", "path", "is_dir", "size", "mtime"}
    assert by_name["sub"]["is_dir"] is True
    assert by_name["a.txt"]["is_dir"] is False
    assert by_name["a.txt"]["size"] == 5
    # directories sort ahead of files
    assert data["entries"][0]["is_dir"] is True


def test_browse_navigates_into_subdir(admin, app):
    box = _sandbox(app)
    deep = box / "deep"
    deep.mkdir(exist_ok=True)
    (deep / "f.bin").write_bytes(b"12345")

    resp = admin.get("/browse/list", query_string={"path": str(deep)})
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["cwd"] == str(deep.resolve())
    assert data["parent"] == data["root"]
    assert data["entries"][0]["name"] == "f.bin"
    assert data["entries"][0]["size"] == 5


def test_browse_rejects_dotdot(admin):
    resp = admin.get("/browse/list", query_string={"path": "/tmp/../etc"})
    assert resp.status_code == 400
    assert "'..'" in resp.get_json()["error"]


def test_browse_confined_to_root(admin):
    resp = admin.get("/browse/list", query_string={"path": "/etc"})
    assert resp.status_code == 403
    assert "allowed root" in resp.get_json()["error"]


def test_browse_permission_gate(viewer):
    resp = viewer.get("/browse/list")
    assert resp.status_code == 403
    assert "wipe permission" in resp.get_json()["error"]
