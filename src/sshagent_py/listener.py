import os
import socket
import struct
import threading

from .message import decode_message_bytes
from .types import SSH_Messages


def setup_listener() -> None:
  socket_address = "/tmp/agent.sock"
  u_sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
  if os.path.exists(socket_address):
    print("removing pre-existing socket entry")
    os.remove(socket_address)

  u_sock.bind(socket_address)
  u_sock.listen()
  print("unix socket was started, waiting for connection")

  try:
    while True:
      conn, _ = u_sock.accept()
      thread = threading.Thread(
        target=handle_connection,
        args=(conn,),
        daemon=True
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
      print('Connection from', str(conn).split(", ")[0][-4:])

      # receive data from the client
      while True:
        # ssh can transfer upto theoretically 4gb of data, i.e. 2 ** 32, uint32
        # bytes, we will have to figure out how
        data = conn.recv(1024)
        message_type = decode_message_bytes(data=data)

        match message_type:
          case SSH_Messages.SSH_AGENTC_REQUEST_IDENTITIES:
            response_bytes = struct.pack(
              '<I', 2
            )
            response_bytes += int(
              SSH_Messages.SSH_AGENT_IDENTITIES_ANSWER.value
            ).to_bytes()
            response_bytes += int(0).to_bytes()
            conn.sendall(response_bytes)

          case SSH_Messages.DEFAULT:
            response_bytes = struct.pack(
              '<I', 1
            )
            response_bytes += int(
              SSH_Messages.SSH_AGENT_SUCCESS.value
            ).to_bytes()
            conn.sendall(response_bytes)
    except (ConnectionResetError, BrokenPipeError):
        pass
    finally:
      # close the connection
      conn.close()
      print("Closing connection")
