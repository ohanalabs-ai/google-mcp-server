"""Tests for GoogleDocsClient tab-aware document reading."""

from unittest.mock import MagicMock, patch

from google_mcp_server.docs_client import GoogleDocsClient


def _paragraph(text: str) -> dict:
    return {"paragraph": {"elements": [{"textRun": {"content": text}}]}}


class TestGoogleDocsClient:
    def _make_client(self, mock_service):
        with patch("google_mcp_server.docs_client.build", return_value=mock_service):
            return GoogleDocsClient(credentials=MagicMock())

    def test_single_tab_document(self):
        mock_service = MagicMock()
        client = self._make_client(mock_service)
        mock_service.documents().get().execute.return_value = {
            "title": "My Doc",
            "tabs": [
                {
                    "tabProperties": {"tabId": "t.0", "title": "Overview"},
                    "documentTab": {"body": {"content": [_paragraph("hello\n")]}},
                }
            ],
        }

        result = client.get_document_tabs("doc123")

        assert result["success"] is True
        assert result["title"] == "My Doc"
        assert len(result["tabs"]) == 1
        assert result["tabs"][0]["title"] == "Overview"
        assert result["tabs"][0]["tabId"] == "t.0"
        assert result["tabs"][0]["depth"] == 0
        assert "hello" in result["tabs"][0]["text"]

        _, kwargs = mock_service.documents().get.call_args
        assert kwargs.get("includeTabsContent") is True

    def test_nested_child_tabs_are_flattened_in_order(self):
        mock_service = MagicMock()
        client = self._make_client(mock_service)
        mock_service.documents().get().execute.return_value = {
            "title": "Parent Doc",
            "tabs": [
                {
                    "tabProperties": {"tabId": "t.0", "title": "Parent"},
                    "documentTab": {"body": {"content": [_paragraph("parent text\n")]}},
                    "childTabs": [
                        {
                            "tabProperties": {"tabId": "t.1", "title": "Child"},
                            "documentTab": {"body": {"content": [_paragraph("child text\n")]}},
                        }
                    ],
                }
            ],
        }

        result = client.get_document_tabs("doc456")

        assert [t["title"] for t in result["tabs"]] == ["Parent", "Child"]
        assert [t["depth"] for t in result["tabs"]] == [0, 1]

    def test_document_without_tabs_falls_back_to_body(self):
        mock_service = MagicMock()
        client = self._make_client(mock_service)
        mock_service.documents().get().execute.return_value = {
            "title": "Old Doc",
            "body": {"content": [_paragraph("legacy content\n")]},
        }

        result = client.get_document_tabs("doc789")

        assert result["success"] is True
        assert len(result["tabs"]) == 1
        assert result["tabs"][0]["tabId"] == ""
        assert "legacy content" in result["tabs"][0]["text"]
