import struct

from src.sshagent_py.types import SSH_Messages


def prepare_response(
  message_type: SSH_Messages,
  content: bytes = bytes("", encoding='utf-8')
) -> bytes:
  # message type is always 1 byte
  content_length = len(content) + 1
  b_content_length = struct.pack(">I", content_length)
  b_message_type = bytes(message_type.value)
  return b_content_length + b_message_type + content
