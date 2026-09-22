import os
import logging
import threading
import socket

from .message import decode_message_bytes
from .types import SSH_Messages
from . import response


logger = logging.getLogger(__name__)


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
        logger.debug(f"Connection from {str(conn).split(', ')[0][-4:]}")

        # receive data from the client
        while True:
            # ssh can transfer upto theoretically 4gb of data, i.e. 2 ** 32, uint32
            # bytes, we will have to figure out how
            data = conn.recv(1024)
            if len(data) == 0:
                logger.debug("client has closed the connection")
                break
            message_type = decode_message_bytes(data=data)

            match message_type:
                case SSH_Messages.SSH_AGENTC_REQUEST_IDENTITIES:
                    response_bytes = response.prepare_response(
                        message_type=SSH_Messages.SSH_AGENT_IDENTITIES_ANSWER,
                    )
                    logger.debug(f"returning indentities list: {response_bytes}")
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
