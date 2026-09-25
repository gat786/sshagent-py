import logging
import struct

from .types import SSH_Messages

logger = logging.getLogger(__name__)


def prepare_response(
    message_type: SSH_Messages,
    content: bytes = b''
) -> bytes:
    # message type is always 1 byte
    content_length = len(content) + 1
    b_content_length = struct.pack(">I", content_length)
    b_message_type = int.to_bytes(message_type.value)
    bytes_res = b_content_length + b_message_type + content
    return bytes_res
