import pytest
import os
import json
import asyncio
from pathlib import Path
from mitmproxy_mcp.core.server import load_traffic_file, export_har


@pytest.mark.asyncio
async def test_path_traversal_denied():
    target_path = Path("/tmp/mitm_traversal_test.har")
    with open(target_path, "w") as f:
        f.write('{"log": {"entries": []}}')
    try:
        result_str = await load_traffic_file("../../../../../tmp/mitm_traversal_test.har")
        result = result_str if isinstance(result_str, dict) else json.loads(result_str)
        assert result["status"] == "error"
        assert "Security Error" in result["message"]
        assert "Access denied" in result["message"]
    finally:
        if target_path.exists():
            os.remove(target_path)


@pytest.mark.asyncio
async def test_valid_path_allowed(tmp_path):
    local_file = Path("test_safe_import.har")
    with open(local_file, "w") as f:
        f.write('{"log": {"entries": []}}')
    try:
        result_str = await load_traffic_file("test_safe_import.har")
        result = result_str if isinstance(result_str, dict) else json.loads(result_str)
        assert result["status"] == "ok"
    finally:
        if local_file.exists():
            os.remove(local_file)


@pytest.mark.asyncio
async def test_sibling_directory_prefix_denied():
    result_str = await load_traffic_file("../" + Path.cwd().name + "-evil/malicious.har")
    result = result_str if isinstance(result_str, dict) else json.loads(result_str)
    assert result["status"] == "error"
    assert "Security Error" in result["message"]
    assert "Access denied" in result["message"]


@pytest.mark.asyncio
async def test_export_har_sibling_prefix_denied():
    result = await export_har("../" + Path.cwd().name + "-evil/malicious.har")
    assert result["status"] == "error"
    assert "Security Error" in result["message"]


@pytest.mark.asyncio
async def test_export_har_valid_subdirectory_allowed(tmp_path):
    subdir_file = Path.cwd() / "test_har_subdir" / "output.har"
    result = await export_har(str(subdir_file))
    assert result["status"] == "ok"
    assert result["entries"] == 0
    if subdir_file.exists():
        subdir_file.unlink()
    if subdir_file.parent.exists():
        try:
            subdir_file.parent.rmdir()
        except Exception:
            pass


@pytest.mark.asyncio
async def test_path_traversal_absolute_outside_denied():
    result = await load_traffic_file("/tmp/outside.har")
    assert result["status"] == "error"
    assert "Security Error" in result["message"]


@pytest.mark.asyncio
async def test_is_relative_to_allows_nested_inside():
    nested = Path.cwd() / "a" / "b" / "c.har"
    result = await export_har(str(nested))
    assert result["status"] == "ok"
    if nested.exists():
        nested.unlink()
    for p in [nested.parent, nested.parent.parent]:
        if p.exists() and p != Path.cwd():
            try:
                p.rmdir()
            except Exception:
                pass
