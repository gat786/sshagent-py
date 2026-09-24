import os
import random
import shutil
import struct
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

from sshagent_py.types import SSH_Messages


@unittest.skipUnless(shutil.which("socat"), "socat is required")
class SocatRejectionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.socket_directory = tempfile.TemporaryDirectory()
        self.socket_path = Path(self.socket_directory.name) / "agent.sock"
        environment = os.environ.copy()
        environment["CUSTOM_SSH_AGENT_SOCK_ADDRESS"] = str(self.socket_path)

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
        self.addCleanup(self._stop_server)
        self._wait_for_socket()

    def tearDown(self) -> None:
        self.socket_directory.cleanup()

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

    def _run_socat(self, request: bytes) -> subprocess.CompletedProcess[bytes]:
        return subprocess.run(
            ["socat", "-", f"UNIX-CONNECT:{self.socket_path}"],
            input=request,
            capture_output=True,
            timeout=5,
            check=False,
        )

    def test_rejects_random_unknown_message_types(self) -> None:
        random_source = random.Random(0x5A17)
        known_message_types = {message.value for message in SSH_Messages}
        requests = []

        for _ in range(16):
            message_type = random_source.randrange(256)
            while message_type in known_message_types:
                message_type = random_source.randrange(256)
            payload = random_source.randbytes(random_source.randrange(32))
            requests.append(struct.pack(">I", len(payload) + 1))
            requests.append(bytes([message_type]))
            requests.append(payload)

        result = self._run_socat(b"".join(requests))

        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertEqual(result.stdout, b"hello\n" * 16)

    def test_rejects_zero_length_message(self) -> None:
        result = self._run_socat(struct.pack(">I", 0))

        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertEqual(result.stdout, b"hello\n")
