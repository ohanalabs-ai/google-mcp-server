"""Google Docs API client for MCP server.

Drive's files().export() (used by GoogleDriveClient._get_file_content) has
no documented support for Google's "tabs" feature - Google's own export
MIME type reference and multiple community reports agree the export API is
not guaranteed to return more than the default/first tab of a multi-tab
document, with no error or warning when content is missing.

The Docs API's documents().get(includeTabsContent=True) is the documented,
reliable way to read every tab's content and title.
"""

import logging
from typing import Any, Dict, List

from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

logger = logging.getLogger(__name__)


class GoogleDocsClient:
    """Client for Google Docs API operations."""

    def __init__(self, credentials: Credentials):
        """
        Initialize the Google Docs client.

        Args:
            credentials: Valid Google OAuth2 credentials
        """
        self.credentials = credentials
        self.service = build('docs', 'v1', credentials=credentials)

    @staticmethod
    def _extract_text(body: Dict[str, Any]) -> str:
        """Flatten a Docs API StructuralElement body into plain text."""
        lines: List[str] = []
        for element in body.get('content', []):
            paragraph = element.get('paragraph')
            if paragraph is not None:
                run_text = ''.join(
                    pe.get('textRun', {}).get('content', '')
                    for pe in paragraph.get('elements', [])
                )
                lines.append(run_text)
                continue
            table = element.get('table')
            if table is not None:
                for row in table.get('tableRows', []):
                    for cell in row.get('tableCells', []):
                        lines.append(GoogleDocsClient._extract_text(cell))
        return '\n'.join(lines)

    @staticmethod
    def _walk_tabs(tabs: List[Dict[str, Any]], depth: int = 0) -> List[Dict[str, Any]]:
        result: List[Dict[str, Any]] = []
        for tab in tabs:
            props = tab.get('tabProperties', {})
            body = tab.get('documentTab', {}).get('body', {})
            result.append({
                'depth': depth,
                'tabId': props.get('tabId', ''),
                'title': props.get('title', '(untitled tab)'),
                'text': GoogleDocsClient._extract_text(body),
            })
            child_tabs = tab.get('childTabs', [])
            if child_tabs:
                result.extend(GoogleDocsClient._walk_tabs(child_tabs, depth + 1))
        return result

    def get_document_tabs(self, document_id: str) -> Dict[str, Any]:
        """
        Get the full text content of every tab in a Google Doc.

        Args:
            document_id: Google Docs document ID (same as the Drive file ID)

        Returns:
            Dictionary with the document title and a flat list of tabs, each
            with its depth (0 for top-level, >0 for nested child tabs),
            tabId, title, and plain-text content.
        """
        try:
            document = self.service.documents().get(
                documentId=document_id,
                includeTabsContent=True,
            ).execute()

            tabs = document.get('tabs')
            if tabs:
                formatted_tabs = self._walk_tabs(tabs)
            else:
                # Older documents (or docs that never used the tabs feature)
                # have no 'tabs' array at all - the body is top-level.
                formatted_tabs = [{
                    'depth': 0,
                    'tabId': '',
                    'title': document.get('title', '(document)'),
                    'text': self._extract_text(document.get('body', {})),
                }]

            return {
                'success': True,
                'title': document.get('title', ''),
                'tabs': formatted_tabs,
            }

        except HttpError as e:
            logger.error(f"HTTP error getting document tabs: {e}")
            return {
                'success': False,
                'error': f"HTTP error: {e.resp.status} - {e.content.decode()}"
            }
        except Exception as e:
            logger.error(f"Error getting document tabs: {e}")
            return {
                'success': False,
                'error': str(e)
            }
