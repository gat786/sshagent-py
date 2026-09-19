from .types import SSH_Messages


def decode_message_bytes(data: bytes) -> SSH_Messages:
  message_length = data[:4]
  try:
    if int(message_length) > 0:
      message_type = data[4]
      contents = data[5:]

      if message_type == SSH_Messages.SSH_AGENTC_REQUEST_IDENTITIES:
        return SSH_Messages.SSH_AGENTC_REQUEST_IDENTITIES
  except ValueError as ve:
    print(
      f"Maybe connecting via socat, first 4 bytes are non-int: {data}"
    )
    return SSH_Messages.DEFAULT
  return SSH_Messages.DEFAULT
