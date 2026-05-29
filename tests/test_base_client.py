"""Tests for BaseClient shared functionality."""

import pytest
from unittest.mock import MagicMock, patch, PropertyMock

from lxml import etree

from axltoolkit._base import BaseClient
from axltoolkit.exceptions import AXLAuthenticationError, AXLConnectionError


@pytest.fixture
def base_client():
    """Create a BaseClient with minimal mocking (no actual network)."""
    with patch("axltoolkit._base.SqliteCache"), \
         patch("pathlib.Path.mkdir"), \
         patch("os.chmod"):
        client = BaseClient(
            username="admin",
            password="secret",
            server_ip="10.0.0.1",
            tls_verify=False,
            timeout=5,
            max_retries=0,
        )
    return client


class TestBaseClientInit:
    def test_server_ip_property(self, base_client):
        assert base_client.server_ip == "10.0.0.1"

    def test_tls_verify_false(self, base_client):
        assert base_client._session.verify is False

    def test_tls_verify_true(self):
        with patch("axltoolkit._base.SqliteCache"), \
             patch("pathlib.Path.mkdir"), \
             patch("os.chmod"):
            client = BaseClient(
                username="admin",
                password="secret",
                server_ip="10.0.0.1",
                tls_verify=True,
                timeout=5,
                max_retries=0,
            )
        assert client._session.verify is True

    def test_tls_verify_ca_bundle_not_found(self):
        with pytest.raises(FileNotFoundError, match="CA bundle not found"):
            with patch("axltoolkit._base.SqliteCache"), \
                 patch("pathlib.Path.mkdir"), \
                 patch("os.chmod"):
                BaseClient(
                    username="admin",
                    password="secret",
                    server_ip="10.0.0.1",
                    tls_verify="/nonexistent/ca.pem",
                    timeout=5,
                    max_retries=0,
                )

    def test_history_enabled_by_default(self, base_client):
        assert base_client._history is not None
        assert base_client._history_enabled is True

    def test_history_disabled(self):
        with patch("axltoolkit._base.SqliteCache"), \
             patch("pathlib.Path.mkdir"), \
             patch("os.chmod"):
            client = BaseClient(
                username="admin",
                password="secret",
                server_ip="10.0.0.1",
                tls_verify=False,
                timeout=5,
                max_retries=0,
                history_enabled=False,
            )
        assert client._history is None
        assert client._plugins == []

    def test_timeout_stored(self, base_client):
        assert base_client._timeout == 5

    def test_invalid_server_ip_rejected(self):
        with pytest.raises(ValueError, match="Invalid server_ip"):
            with patch("axltoolkit._base.SqliteCache"), \
                 patch("pathlib.Path.mkdir"), \
                 patch("os.chmod"):
                BaseClient(
                    username="admin",
                    password="secret",
                    server_ip="evil.com/foo#bar",
                    tls_verify=False,
                    timeout=5,
                    max_retries=0,
                )

    def test_valid_fqdn_accepted(self):
        with patch("axltoolkit._base.SqliteCache"), \
             patch("pathlib.Path.mkdir"), \
             patch("os.chmod"):
            client = BaseClient(
                username="admin",
                password="secret",
                server_ip="ucm-pub.example.com",
                tls_verify=False,
                timeout=5,
                max_retries=0,
            )
        assert client.server_ip == "ucm-pub.example.com"


class TestLastRequestDebug:
    def test_returns_none_with_no_history(self, base_client):
        # HistoryPlugin raises IndexError when buffer is empty;
        # last_request_debug should catch that and return None
        result = base_client.last_request_debug()
        assert result is None

    def test_returns_none_with_history_disabled(self):
        with patch("axltoolkit._base.SqliteCache"), \
             patch("pathlib.Path.mkdir"), \
             patch("os.chmod"):
            client = BaseClient(
                username="admin",
                password="secret",
                server_ip="10.0.0.1",
                tls_verify=False,
                timeout=5,
                max_retries=0,
                history_enabled=False,
            )
        assert client.last_request_debug() is None


# ── Envelope redaction tests ─────────────────────────────────────────


class TestRedactEnvelope:
    """Verify that sensitive XML element text is redacted."""

    def test_password_element_is_redacted(self):
        env = etree.fromstring(
            b"<root>"
            b"  <userid>admin</userid>"
            b"  <password>SuperSecret123!</password>"
            b"</root>"
        )
        out = BaseClient._redact_envelope(env).decode()
        assert "SuperSecret123!" not in out
        assert "[REDACTED]" in out
        assert "admin" in out  # non-sensitive fields preserved

    def test_handles_namespaced_elements(self):
        env = etree.fromstring(
            b'<ns:addUser xmlns:ns="http://example.com">'
            b"  <ns:userid>jsmith</ns:userid>"
            b"  <ns:password>hunter2</ns:password>"
            b"</ns:addUser>"
        )
        out = BaseClient._redact_envelope(env).decode()
        assert "hunter2" not in out
        assert "[REDACTED]" in out

    def test_case_insensitive_matching(self):
        env = etree.fromstring(
            b"<root>"
            b"  <Password>caps</Password>"
            b"  <PASSWORD>shout</PASSWORD>"
            b"  <pAsSwOrD>mixed</pAsSwOrD>"
            b"</root>"
        )
        out = BaseClient._redact_envelope(env).decode()
        assert "caps" not in out
        assert "shout" not in out
        assert "mixed" not in out
        assert out.count("[REDACTED]") == 3

    def test_multiple_sensitive_field_types(self):
        env = etree.fromstring(
            b"<root>"
            b"  <password>p1</password>"
            b"  <secretCode>s1</secretCode>"
            b"  <apiKey>k1</apiKey>"
            b"  <token>t1</token>"
            b"  <ldapPassword>l1</ldapPassword>"
            b"</root>"
        )
        out = BaseClient._redact_envelope(env).decode()
        for secret in ("p1", "s1", "k1", "t1", "l1"):
            assert secret not in out
        assert out.count("[REDACTED]") == 5

    def test_does_not_mutate_original(self):
        env = etree.fromstring(
            b"<root><password>SuperSecret123!</password></root>"
        )
        _ = BaseClient._redact_envelope(env)
        # Original tree must still have the real text — zeep needs to
        # be able to re-serialize the live history accurately.
        assert env.find("password").text == "SuperSecret123!"

    def test_empty_text_is_left_alone(self):
        env = etree.fromstring(
            b"<root><password/><password></password></root>"
        )
        out = BaseClient._redact_envelope(env).decode()
        # Empty/none text shouldn't get replaced with "[REDACTED]"
        assert "[REDACTED]" not in out

    def test_non_sensitive_elements_pass_through(self):
        env = etree.fromstring(
            b"<root>"
            b"  <name>SEP001122334455</name>"
            b"  <description>desk phone</description>"
            b"</root>"
        )
        out = BaseClient._redact_envelope(env).decode()
        assert "SEP001122334455" in out
        assert "desk phone" in out
        assert "[REDACTED]" not in out

    def test_none_envelope_returns_empty(self):
        assert BaseClient._redact_envelope(None) == b""

    def test_comments_and_pis_are_ignored(self):
        env = etree.fromstring(
            b"<root>"
            b"<!-- a comment -->"
            b"<password>secret</password>"
            b"<?pi target?>"
            b"</root>"
        )
        out = BaseClient._redact_envelope(env).decode()
        assert "secret" not in out
        assert "[REDACTED]" in out


class TestForbidDtd:
    """The zeep Settings should reject DOCTYPE declarations."""

    def test_settings_passes_forbid_dtd_true(self, base_client):
        with patch("axltoolkit._base.Client") as MockClient:
            with patch("axltoolkit._base.Transport"):
                base_client._create_zeep_client("/fake/wsdl.wsdl")
                call_kwargs = MockClient.call_args[1]
                settings = call_kwargs["settings"]
                assert settings.forbid_dtd is True
                assert settings.strict is False


class TestCheckConnectivity:
    def test_success(self, base_client):
        with patch.object(base_client._session, "get") as mock_get:
            mock_get.return_value = MagicMock(status_code=200)
            assert base_client.check_connectivity() is True

    def test_auth_failure(self, base_client):
        with patch.object(base_client._session, "get") as mock_get:
            mock_get.return_value = MagicMock(status_code=401)
            with pytest.raises(AXLAuthenticationError, match="HTTP 401"):
                base_client.check_connectivity()

    def test_connection_error(self, base_client):
        import requests
        with patch.object(base_client._session, "get") as mock_get:
            mock_get.side_effect = requests.ConnectionError("Connection refused")
            with pytest.raises(AXLConnectionError, match="Cannot reach"):
                base_client.check_connectivity()


class TestCreateZeepClient:
    def test_creates_client_with_plugins(self, base_client):
        with patch("axltoolkit._base.Client") as MockClient:
            with patch("axltoolkit._base.Transport"):
                base_client._create_zeep_client("/fake/wsdl.wsdl")
                MockClient.assert_called_once()
                call_kwargs = MockClient.call_args[1]
                assert call_kwargs["plugins"] == base_client._plugins
