import logging

from .types import SSH_Messages, supported_incoming_messages

logger = logging.getLogger(__name__)


def parse_message_type(value: int) -> SSH_Messages | None:
    try:
        return SSH_Messages(value)
    except ValueError:
        return None


def decode_message_bytes(data: bytes) -> SSH_Messages:
    logger.debug(f"received message: {data}")

    if len(data) < 4:
        logger.debug("invalid message detected")
        return SSH_Messages.INVALID

    message_length = int.from_bytes(data[:4], byteorder="big")
    logger.debug(f"received message of length: {message_length}")
    if message_length == 0 or len(data) != message_length + 4:
        logger.warning("invalid SSH-agent packet length: %d", len(data))
        return SSH_Messages.INVALID

    message_type = data[4]
    logger.debug(f"message type: {message_type}")
    ssh_request_mtype = parse_message_type(message_type)
    if ssh_request_mtype is None:
        return SSH_Messages.INVALID
    if ssh_request_mtype in supported_incoming_messages:
        logger.debug(f"supported incoming request of type: {ssh_request_mtype}")
        return ssh_request_mtype
    logger.warning(
        f"unsupported request received of type: {ssh_request_mtype}, full data: {data}"
    )
    return SSH_Messages.INVALID
