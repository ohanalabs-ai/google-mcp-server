"""Tests for Google authentication module."""

import os
import tempfile
import pytest
from unittest.mock import Mock, patch, MagicMock
from pathlib import Path

from google_mcp_server.auth import GoogleAuthManager


class TestGoogleAuthManager:
    """Test GoogleAuthManager class."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.client_id = "test_client_id"
        self.client_secret = "test_client_secret"
        self.redirect_uri = "http://localhost:8080"
    
    def test_init(self):
        """Test GoogleAuthManager initialization."""
        auth_manager = GoogleAuthManager(
            client_id=self.client_id,
            client_secret=self.client_secret,
            redirect_uri=self.redirect_uri
        )
        
        assert auth_manager.client_id == self.client_id
        assert auth_manager.client_secret == self.client_secret
        assert auth_manager.redirect_uri == self.redirect_uri
        assert len(auth_manager.scopes) > 0
    
    def test_init_with_additional_scopes(self):
        """Test initialization with additional scopes."""
        additional_scopes = ["https://www.googleapis.com/auth/spreadsheets"]
        
        auth_manager = GoogleAuthManager(
            client_id=self.client_id,
            client_secret=self.client_secret,
            redirect_uri=self.redirect_uri,
            additional_scopes=additional_scopes
        )
        
        assert additional_scopes[0] in auth_manager.scopes
    
    @patch('google_mcp_server.auth.Path.home')
    def test_credentials_directory_creation(self, mock_home):
        """Test that credentials directory is created."""
        with tempfile.TemporaryDirectory() as temp_dir:
            mock_home.return_value = Path(temp_dir)
            
            auth_manager = GoogleAuthManager(
                client_id=self.client_id,
                client_secret=self.client_secret
            )
            
            expected_dir = Path(temp_dir) / '.config' / 'google-mcp-server'
            assert auth_manager.credentials_dir == expected_dir
            assert expected_dir.exists()
    
    @patch('google_mcp_server.auth.Credentials')
    @patch('google_mcp_server.auth.Path.home')
    def test_get_credentials_existing_valid(self, mock_home, mock_credentials_class):
        """Test getting existing valid credentials."""
        with tempfile.TemporaryDirectory() as temp_dir:
            mock_home.return_value = Path(temp_dir)
            
            # Create mock credentials
            mock_creds = Mock()
            mock_creds.valid = True
            mock_creds.expired = False
            mock_credentials_class.from_authorized_user_file.return_value = mock_creds
            
            # Create token file
            token_file = Path(temp_dir) / '.config' / 'google-mcp-server' / 'token.json'
            token_file.parent.mkdir(parents=True, exist_ok=True)
            token_file.write_text('{"token": "test"}')
            
            auth_manager = GoogleAuthManager(
                client_id=self.client_id,
                client_secret=self.client_secret
            )
            
            result = auth_manager.get_credentials()
            assert result == mock_creds
    
    def test_get_user_info_no_credentials(self):
        """Test getting user info with no credentials."""
        with patch.object(GoogleAuthManager, 'get_credentials', return_value=None):
            auth_manager = GoogleAuthManager(
                client_id=self.client_id,
                client_secret=self.client_secret
            )
            
            result = auth_manager.get_user_info()
            assert result is None
    
    @patch('google_mcp_server.auth.build')
    def test_get_user_info_success(self, mock_build):
        """Test successful user info retrieval."""
        # Mock credentials
        mock_creds = Mock()
        
        # Mock service
        mock_service = Mock()
        mock_userinfo = Mock()
        mock_userinfo.get.return_value.execute.return_value = {
            'name': 'Test User',
            'email': 'test@example.com'
        }
        mock_service.userinfo.return_value = mock_userinfo
        mock_build.return_value = mock_service
        
        with patch.object(GoogleAuthManager, 'get_credentials', return_value=mock_creds):
            auth_manager = GoogleAuthManager(
                client_id=self.client_id,
                client_secret=self.client_secret
            )
            
            result = auth_manager.get_user_info()
            assert result['name'] == 'Test User'
            assert result['email'] == 'test@example.com'
    
    def test_test_authentication_success(self):
        """Test successful authentication test."""
        mock_user_info = {'name': 'Test User', 'email': 'test@example.com'}
        
        with patch.object(GoogleAuthManager, 'get_user_info', return_value=mock_user_info):
            auth_manager = GoogleAuthManager(
                client_id=self.client_id,
                client_secret=self.client_secret
            )
            
            result = auth_manager.test_authentication()
            assert result is True
    
    def test_test_authentication_failure(self):
        """Test failed authentication test."""
        with patch.object(GoogleAuthManager, 'get_user_info', return_value=None):
            auth_manager = GoogleAuthManager(
                client_id=self.client_id,
                client_secret=self.client_secret
            )

            result = auth_manager.test_authentication()
            assert result is False

    def test_init_defaults_are_container_safe(self):
        """open_browser defaults False, callback_bind_addr defaults 0.0.0.0.

        These defaults matter because this server normally runs inside a
        Docker container with no browser installed and no published port
        bound to localhost specifically.
        """
        auth_manager = GoogleAuthManager(
            client_id=self.client_id,
            client_secret=self.client_secret
        )

        assert auth_manager.open_browser is False
        assert auth_manager.callback_bind_addr == "0.0.0.0"

    @patch('google_mcp_server.auth.InstalledAppFlow')
    def test_oauth_flow_falls_back_when_no_browser_available(self, mock_flow_class):
        """A webbrowser.Error must not abort the flow before printing the URL."""
        mock_flow = Mock()
        mock_flow.run_local_server.return_value = Mock()
        mock_flow_class.from_client_config.return_value = mock_flow

        auth_manager = GoogleAuthManager(
            client_id=self.client_id,
            client_secret=self.client_secret,
            open_browser=True,
        )

        with patch('google_mcp_server.auth.webbrowser.get', side_effect=__import__('webbrowser').Error("no runnable browser")):
            creds = auth_manager._run_oauth_flow()

        assert creds is not None
        _, kwargs = mock_flow.run_local_server.call_args
        assert kwargs.get("open_browser") is False

    @patch('google_mcp_server.auth.InstalledAppFlow')
    def test_oauth_flow_passes_bind_addr_separately_from_host(self, mock_flow_class):
        """The callback server must bind callback_bind_addr, not the advertised host."""
        mock_flow = Mock()
        mock_flow.run_local_server.return_value = Mock()
        mock_flow_class.from_client_config.return_value = mock_flow

        auth_manager = GoogleAuthManager(
            client_id=self.client_id,
            client_secret=self.client_secret,
            callback_bind_addr="0.0.0.0",
        )

        auth_manager._run_oauth_flow()

        _, kwargs = mock_flow.run_local_server.call_args
        assert kwargs.get("host") == "localhost"
        assert kwargs.get("bind_addr") == "0.0.0.0"