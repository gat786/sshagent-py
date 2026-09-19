from . import listener


def main() -> None:
  print("Hello from sshagent-py!")
  listener.setup_listener()
