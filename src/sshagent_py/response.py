import logging
import struct

from .types import SSH_Messages


logger = logging.getLogger(__name__)


def prepare_response(
    message_type: SSH_Messages, content: bytes = bytes("", encoding="utf-8")
) -> bytes:
    # message type is always 1 byte
    logger.debug(f"message_type: {message_type}, content: {content},")
    content_length = len(content) + 1
    b_content_length = struct.pack(">I", content_length)
    b_message_type = int.to_bytes(message_type.value)
    logger.debug(f"content leng: {b_content_length}, message_type: {b_message_type}")
    bytes_res = b_content_length + b_message_type + content
    logger.debug(f"bytes response: {bytes_res}")
    return bytes_res
