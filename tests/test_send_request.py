import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from mitmproxy_mcp.core.server import send_request, controller


@pytest.mark.asyncio
async def test_send_request_proxy_not_running():
    original = controller.running
    controller.running = False
    try:
        result = await send_request(method="GET", url="https://example.com")
        assert result["status"] == "error"
        assert "isn't running" in result["message"]
    finally:
        controller.running = original


@pytest.mark.asyncio
async def test_send_request_invalid_headers_json():
    original = controller.running
    controller.running = True
    try:
        result = await send_request(
            method="GET",
            url="https://example.com",
            headers_json="{invalid json",
        )
        assert result["status"] == "error"
        assert "valid JSON" in result["message"]
    finally:
        controller.running = original


@pytest.mark.asyncio
async def test_send_request_method_uppercased():
    original = controller.running
    controller.running = True
    try:
        mock_response = MagicMock()
        mock_response.status_code = 200

        mock_session = AsyncMock()
        mock_session.request = AsyncMock(return_value=mock_response)
        mock_session.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session.__aexit__ = AsyncMock(return_value=False)

        with patch("mitmproxy_mcp.core.server.AsyncSession", return_value=mock_session):
            result = await send_request(method="get", url="https://example.com")

        assert result["status"] == "ok"
        call_kwargs = mock_session.request.call_args[1]
        assert call_kwargs["method"] == "GET"
    finally:
        controller.running = original


@pytest.mark.asyncio
async def test_send_request_success():
    original = controller.running
    controller.running = True
    try:
        mock_response = MagicMock()
        mock_response.status_code = 201

        mock_session = AsyncMock()
        mock_session.request = AsyncMock(return_value=mock_response)
        mock_session.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session.__aexit__ = AsyncMock(return_value=False)

        with patch("mitmproxy_mcp.core.server.AsyncSession", return_value=mock_session):
            result = await send_request(
                method="POST",
                url="https://api.example.com/data",
                headers_json='{"Content-Type": "application/json"}',
                body='{"key": "value"}',
            )

        assert result["status"] == "ok"
        assert "201" in result["message"]
        call_kwargs = mock_session.request.call_args[1]
        assert call_kwargs["data"] == '{"key": "value"}'
        assert call_kwargs["headers"] == {"Content-Type": "application/json"}
    finally:
        controller.running = original


@pytest.mark.asyncio
async def test_send_request_failure():
    original = controller.running
    controller.running = True
    try:
        mock_session = AsyncMock()
        mock_session.request = AsyncMock(side_effect=Exception("Connection refused"))
        mock_session.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session.__aexit__ = AsyncMock(return_value=False)

        with patch("mitmproxy_mcp.core.server.AsyncSession", return_value=mock_session):
            result = await send_request(method="GET", url="https://example.com")

        assert result["status"] == "error"
        assert "Connection refused" in result["message"]
    finally:
        controller.running = original
