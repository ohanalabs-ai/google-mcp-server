"""Tests for GoogleDriveClient shared-drive support."""

from unittest.mock import MagicMock, patch

from google_mcp_server.drive_client import GoogleDriveClient


class TestSharedDriveSupport:
    """files().get()/files().delete() must set supportsAllDrives=True.

    Without it, the Drive API returns a 404 (not a 403) for any file that
    lives in a Shared Drive, even when the caller has access to it.
    """

    def _make_client(self, mock_service):
        with patch("google_mcp_server.drive_client.build", return_value=mock_service):
            return GoogleDriveClient(credentials=MagicMock())

    def test_get_file_passes_supports_all_drives(self):
        mock_service = MagicMock()
        client = self._make_client(mock_service)

        mock_service.files().get().execute.return_value = {
            "id": "file123",
            "name": "Doc",
            "mimeType": "application/vnd.google-apps.document",
            "createdTime": "2026-01-01T00:00:00Z",
            "modifiedTime": "2026-01-01T00:00:00Z",
        }

        result = client.get_file(file_id="file123", include_content=False)

        assert result["success"] is True
        _, kwargs = mock_service.files().get.call_args
        assert kwargs.get("supportsAllDrives") is True

    def test_delete_file_passes_supports_all_drives(self):
        mock_service = MagicMock()
        client = self._make_client(mock_service)

        mock_service.files().get().execute.return_value = {"name": "Doc"}

        client.delete_file(file_id="file123")

        get_args, get_kwargs = mock_service.files().get.call_args
        assert get_kwargs.get("supportsAllDrives") is True
        delete_args, delete_kwargs = mock_service.files().delete.call_args
        assert delete_kwargs.get("supportsAllDrives") is True
