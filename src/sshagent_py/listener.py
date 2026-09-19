import os
import socket
import threading


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

def handle_connection(conn):
    try:
      print('Connection from', str(conn).split(", ")[0][-4:])

      # receive data from the client
      while True:
        data = conn.recv(1024)
        request_str = data.decode()
        if not data:
            break
        print('Received data:', request_str.strip("\n"))

        # Send a response back to the client
        conn.sendall(request_str.encode())
    except (ConnectionResetError, BrokenPipeError):
        pass
    finally:
      # close the connection
      conn.close()
      print("Closing connection")
