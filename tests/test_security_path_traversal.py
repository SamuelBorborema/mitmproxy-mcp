import pytest
import os
import json
import asyncio
from pathlib import Path
from mitmproxy_mcp.core.server import load_traffic_file

@pytest.mark.asyncio
async def test_path_traversal_denied():
    """Verify that accessing files outside the project root is blocked."""
    # Create a dummy file in /tmp
    target_path = Path("/tmp/mitm_traversal_test.har")
    with open(target_path, "w") as f:
        f.write('{"log": {"entries": []}}')
    
    try:
        # Attempt to access it via relative traversal
        # We know we are in /home/snap/Development/mitmproxy-mcp/tests or similar
        result_str = await load_traffic_file("../../../../../tmp/mitm_traversal_test.har")
        result = json.loads(result_str)
        
        assert result["status"] == "error"
        assert "Security Error" in result["message"]
        assert "Access denied" in result["message"]
        
    finally:
        if target_path.exists():
            os.remove(target_path)

@pytest.mark.asyncio
async def test_valid_path_allowed(tmp_path):
    """Verify that accessing files within the project root still works."""
    # Create a file inside the project (using tmp_path which pytest handles)
    # However, our fix restricts to CWD, so let's create it in the current dir
    local_file = Path("test_safe_import.har")
    with open(local_file, "w") as f:
        f.write('{"log": {"entries": []}}')
        
    try:
        result_str = await load_traffic_file("test_safe_import.har")
        result = json.loads(result_str)
        
        # Should NOT be a security error
        assert result["status"] == "ok"
    finally:
        if local_file.exists():
            os.remove(local_file)
