import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

_HAS_OPENSSH = all(shutil.which(tool) for tool in ("ssh-add", "ssh-keygen"))


@unittest.skipUnless(_HAS_OPENSSH, "ssh-add and ssh-keygen are required")
class SshAddIntegrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.socket_directory = tempfile.TemporaryDirectory()
        self.socket_path = Path(self.socket_directory.name) / "agent.sock"
        environment = os.environ.copy()
        environment["CUSTOM_SSH_AGENT_SOCK_ADDRESS"] = str(self.socket_path)
        environment["SSH_AGENT_LOGLEVEL"] = "WARNING"

        self.server = subprocess.Popen(
            [
                sys.executable,
                "-c",
                "from sshagent_py.listener import setup_listener; setup_listener()",
            ],
            env=environment,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        self.addCleanup(self.socket_directory.cleanup)
        self.addCleanup(self._stop_server)
        self._wait_for_socket()

        self.ssh_environment = environment.copy()
        self.ssh_environment["SSH_AUTH_SOCK"] = str(self.socket_path)
        self.ssh_environment.pop("SSH_AGENT_PID", None)

    def _wait_for_socket(self) -> None:
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if self.server.poll() is not None:
                self.fail("SSH-agent listener exited before creating its socket")
            if self.socket_path.exists():
                return
            time.sleep(0.01)
        self.fail("timed out waiting for the SSH-agent socket")

    def _stop_server(self) -> None:
        if self.server.poll() is None:
            self.server.terminate()
            try:
                self.server.wait(timeout=2)
            except subprocess.TimeoutExpired:
                self.server.kill()
                self.server.wait()

    def _generate_key(self, key_type: str) -> Path:
        key_path = Path(self.socket_directory.name) / f"id_{key_type}"
        command = [
            "ssh-keygen",
            "-q",
            "-t",
            key_type,
            "-N",
            "",
            "-C",
            "sshagent-py-test",
            "-f",
            str(key_path),
        ]
        if key_type == "rsa":
            command.extend(["-b", "2048"])

        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        return key_path

    def _run_ssh_add(self, key_path: Path) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["ssh-add", str(key_path)],
            env=self.ssh_environment,
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )

    def test_add_ed25519_key_succeeds(self) -> None:
        result = self._run_ssh_add(self._generate_key("ed25519"))

        self.assertEqual(result.returncode, 0, result.stderr)

        listing = subprocess.run(
            ["ssh-add", "-l"],
            env=self.ssh_environment,
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        self.assertEqual(listing.returncode, 0, listing.stderr)
        self.assertIn("ED25519", listing.stdout)

    def test_add_rsa_key_fails(self) -> None:
        result = self._run_ssh_add(self._generate_key("rsa"))

        self.assertNotEqual(result.returncode, 0, result.stdout)
