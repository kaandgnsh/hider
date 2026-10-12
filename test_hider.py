import hashlib
import hmac
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import hider


class ProxyLogTests(unittest.TestCase):
    def test_masks_proxy_credentials_and_query(self):
        result = hider.safe_proxy_label(
            "http://alice:very-secret@proxy.example:8080/path?token=secret"
        )
        self.assertEqual(result, "http://proxy.example:8080")
        self.assertNotIn("alice", result)
        self.assertNotIn("very-secret", result)
        self.assertNotIn("token", result)

    def test_supports_bare_host_port_and_ipv6(self):
        self.assertEqual(
            hider.safe_proxy_label("127.0.0.1:8888"),
            "http://127.0.0.1:8888",
        )
        self.assertEqual(
            hider.safe_proxy_label("socks5://[::1]:9050"),
            "socks5://[::1]:9050",
        )


class SafeCookieTests(unittest.TestCase):
    def test_safe_cookie_handshake(self):
        cookie = b"C" * 32
        server_nonce = b"S" * 32

        with tempfile.TemporaryDirectory() as directory:
            cookie_path = Path(directory) / "control.authcookie"
            cookie_path.write_bytes(cookie)

            class FakeSocket:
                def __init__(self):
                    self.response = bytearray()
                    self.client_authenticated = False
                    self.client_nonce = None

                def sendall(self, payload):
                    command = payload.decode("ascii")
                    if command == "PROTOCOLINFO 1\r\n":
                        self.response.extend(
                            (
                                "250-PROTOCOLINFO 1\r\n"
                                "250-AUTH METHODS=SAFECOOKIE,COOKIE "
                                f'COOKIEFILE="{cookie_path}"\r\n'
                                '250-VERSION Tor="0.4.test"\r\n'
                                "250 OK\r\n"
                            ).encode("ascii")
                        )
                    elif command.startswith("AUTHCHALLENGE SAFECOOKIE "):
                        self.client_nonce = bytes.fromhex(command.split()[2])
                        message = cookie + self.client_nonce + server_nonce
                        server_key = b"Tor safe cookie authentication server-to-controller hash"
                        server_hash = hmac.new(
                            server_key, message, hashlib.sha256
                        ).hexdigest()
                        self.response.extend(
                            (
                                "250 AUTHCHALLENGE SERVERHASH="
                                f"{server_hash} SERVERNONCE={server_nonce.hex()}\r\n"
                            ).encode("ascii")
                        )
                    elif command.startswith("AUTHENTICATE "):
                        message = cookie + self.client_nonce + server_nonce
                        client_key = b"Tor safe cookie authentication controller-to-server hash"
                        expected = hmac.new(
                            client_key, message, hashlib.sha256
                        ).hexdigest()
                        self.client_authenticated = (
                            command == f"AUTHENTICATE {expected}\r\n"
                        )
                        self.response.extend(
                            b"250 OK\r\n"
                            if self.client_authenticated
                            else b"515 Authentication failed\r\n"
                        )
                    else:
                        raise AssertionError(f"Unexpected command: {command!r}")

                def recv(self, size):
                    if not self.response:
                        return b""
                    chunk = bytes(self.response[:size])
                    del self.response[:size]
                    return chunk

            sock = FakeSocket()
            self.assertTrue(hider.TorBackend()._auth(sock))
            self.assertTrue(sock.client_authenticated)

    def test_rejects_tampered_server_hash(self):
        cookie = b"C" * 32
        server_nonce = b"S" * 32

        with tempfile.TemporaryDirectory() as directory:
            cookie_path = Path(directory) / "control.authcookie"
            cookie_path.write_bytes(cookie)

            class TamperedSocket:
                def __init__(self):
                    self.response = bytearray()

                def sendall(self, payload):
                    command = payload.decode("ascii")
                    if command == "PROTOCOLINFO 1\r\n":
                        self.response.extend(
                            (
                                "250-AUTH METHODS=SAFECOOKIE,COOKIE "
                                f'COOKIEFILE="{cookie_path}"\r\n'
                                "250 OK\r\n"
                            ).encode("ascii")
                        )
                    elif command.startswith("AUTHCHALLENGE SAFECOOKIE "):
                        self.response.extend(
                            (
                                "250 AUTHCHALLENGE SERVERHASH="
                                + ("00" * 32)
                                + " SERVERNONCE="
                                + server_nonce.hex()
                                + "\r\n"
                            ).encode("ascii")
                        )
                    else:
                        raise AssertionError(
                            "Authentication should stop after an invalid server hash."
                        )

                def recv(self, size):
                    chunk = bytes(self.response[:size])
                    del self.response[:size]
                    return chunk

            self.assertFalse(hider.TorBackend()._auth(TamperedSocket()))


class TorConfigTests(unittest.TestCase):
    def test_refuses_disabled_cookie_authentication(self):
        with tempfile.TemporaryDirectory() as directory:
            torrc = Path(directory) / "torrc"
            torrc.write_text(
                "SocksPort 9050\nControlPort 9051\nCookieAuthentication 0\n",
                encoding="utf-8",
            )
            with patch.object(hider, "_find_torrc", return_value=torrc):
                self.assertFalse(hider._configure_torrc())
            self.assertIn(
                "CookieAuthentication 0",
                torrc.read_text(encoding="utf-8"),
            )

    def test_adds_cookie_authentication_when_missing(self):
        with tempfile.TemporaryDirectory() as directory:
            torrc = Path(directory) / "torrc"
            torrc.write_text("# managed manually\n", encoding="utf-8")
            with patch.object(hider, "_find_torrc", return_value=torrc):
                self.assertTrue(hider._configure_torrc())
            content = torrc.read_text(encoding="utf-8")
            self.assertIn("SocksPort 9050", content)
            self.assertIn("ControlPort 9051", content)
            self.assertIn("CookieAuthentication 1", content)
            self.assertNotIn("CookieAuthentication 0", content)

    def test_rejects_conflicting_control_port_without_editing(self):
        with tempfile.TemporaryDirectory() as directory:
            torrc = Path(directory) / "torrc"
            original = "ControlPort 9151\nCookieAuthentication 1\n"
            torrc.write_text(original, encoding="utf-8")
            with patch.object(hider, "_find_torrc", return_value=torrc):
                self.assertFalse(hider._configure_torrc())
            self.assertEqual(torrc.read_text(encoding="utf-8"), original)


class TorLifecycleTests(unittest.TestCase):
    def test_stop_does_not_stop_or_kill_global_tor(self):
        with patch.object(hider, "run") as run:
            hider.TorBackend().stop()
        run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
