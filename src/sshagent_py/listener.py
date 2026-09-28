import base64
import hashlib
import logging
import os
import socket
import threading

from . import response
from .add_key import get_parsed_key
from .message import decode_message_bytes, parse_ssh_request
from .types import (
    EDDsaKey,
    SSH_Messages,
    SSHCryptoKey,
    SshRequest,
    int_uint32,
    len_wrap_bytes,
    str_bytes,
)

logger = logging.getLogger(__name__)
_PACKET_LENGTH_BYTES = 4
_RECV_CHUNK_SIZE = 64 * 1024

identities: dict[str, SSHCryptoKey] = {}


def split_data(data: bytes) -> SshRequest:
    """should be called on a valid request only, returns size, method and body as a dataclass representation"""
    return SshRequest(
        size_of_request=0, request_method=1, request_body=bytes("a", encoding="utf-8")
    )


def _recv_exactly(conn: socket.socket, size: int) -> bytes | None:
    data = bytearray()
    while len(data) < size:
        chunk = conn.recv(min(size - len(data), _RECV_CHUNK_SIZE))
        if not chunk:
            return None
        data.extend(chunk)
    return bytes(data)


def receive_packet(conn: socket.socket) -> bytes | None:
    """Read one complete SSH-agent packet from a stream socket."""
    header = _recv_exactly(conn, _PACKET_LENGTH_BYTES)
    if header is None:
        return None

    message_length = int.from_bytes(header, byteorder="big")
    payload = _recv_exactly(conn, message_length)
    if payload is None:
        logger.warning("client disconnected before the full packet was received")
        return None
    return header + payload


def setup_listener() -> None:
    socket_address = os.getenv("CUSTOM_SSH_AGENT_SOCK_ADDRESS", "/tmp/agent.sock")
    logger.info(f"using socket address: {socket_address}")

    u_sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    if os.path.exists(socket_address):
        logger.debug("removing pre-existing socket entry")
        os.remove(socket_address)

    u_sock.bind(socket_address)
    u_sock.listen()
    logger.debug("unix socket was started, waiting for connection")

    try:
        while True:
            logger.debug("a new connection was initiated, processing message")
            conn, _ = u_sock.accept()
            thread = threading.Thread(
                target=handle_connection, args=(conn,), daemon=True
            )
            thread.start()
    except KeyboardInterrupt:
        print("Interrupt received: shutting down")
    finally:
        u_sock.close()
        if os.path.exists(socket_address):
            os.unlink(socket_address)


def handle_connection(conn: socket.socket):
    try:
        logger.info(f"Connection from {str(conn).split(', ')[0][-4:]}")
        while True:
            data = receive_packet(conn)
            if data is None:
                logger.debug("client closed the connection")
                break
            message_type = decode_message_bytes(data=data)
            match message_type:
                case SSH_Messages.SSH_AGENTC_REQUEST_IDENTITIES:
                    identities_count = len(identities)
                    res = int_uint32(identities_count)

                    for ssh_key in identities.values():
                        if isinstance(ssh_key, EDDsaKey):
                            key_blob = ssh_key.key_blob
                            comment = ssh_key.comment
                            comment_b = str_bytes(comment)
                            res = res + len_wrap_bytes(key_blob) + comment_b

                    response_bytes = response.prepare_response(
                        message_type=SSH_Messages.SSH_AGENT_IDENTITIES_ANSWER,
                        content=res,
                    )

                    logger.debug(f"returning indentities list: {response_bytes}")
                    conn.sendall(response_bytes)

                case SSH_Messages.SSH_AGENTC_SIGN_REQUEST:
                    response_bytes = response.prepare_response(
                        message_type=SSH_Messages.SSH_AGENT_SUCCESS,
                    )
                    conn.sendall(response_bytes)
                case SSH_Messages.SSH_AGENTC_ADD_IDENTITY:
                    ssh_request = parse_ssh_request(data=data)
                    ssh_key: SSHCryptoKey | None = get_parsed_key(
                        data=ssh_request.request_body
                    )
                    if isinstance(ssh_key, EDDsaKey):
                        kb = str_bytes(ssh_key.type) + len_wrap_bytes(
                            ssh_key.public_key
                        )
                        k_digest = hashlib.sha256(kb).digest()
                        fingerprint = base64.b64encode(k_digest).decode().rstrip("=")
                        identities[fingerprint] = ssh_key
                        response_bytes = response.prepare_response(
                            message_type=SSH_Messages.SSH_AGENT_SUCCESS
                        )
                        conn.sendall(response_bytes)
                    else:
                        logger.warning(
                            "the client as of now only supports adding EDDsa Keys."
                        )

                        response_bytes = response.prepare_response(
                            message_type=SSH_Messages.SSH_AGENT_FAILURE
                        )
                        conn.sendall(response_bytes)

                case SSH_Messages.INVALID:
                    response_bytes = bytes("hello\n", "utf-8")
                    logger.debug(f"returning invalid response: {response_bytes}")
                    conn.sendall(response_bytes)

                case SSH_Messages.DEFAULT:
                    response_bytes = response.prepare_response(
                        message_type=SSH_Messages.DEFAULT
                    )
                    logger.debug(f"returning default message: {response_bytes}")
                    conn.sendall(response_bytes)

    except ConnectionResetError, BrokenPipeError:
        pass
    finally:
        # close the connection
        conn.close()
        logger.info("Closing connection")
