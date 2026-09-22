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

    # if the message is less than 4 bytes than it is not a valid message
    if len(data) < 4:
        logger.debug("invalid message detected")
        return SSH_Messages.INVALID

    message_length = data[:4]
    try:
        int_message_length = int.from_bytes(message_length)
        logger.debug(f"recieved message of length: {int_message_length}")
        if int_message_length > 0:
            # byte automatically gets converted to int
            message_type: int = data[4]
            logger.debug(f"message type: {message_type}")
            ssh_request_mtype = parse_message_type(message_type)
            if ssh_request_mtype is None:
                return SSH_Messages.INVALID
            if ssh_request_mtype in supported_incoming_messages:
                logger.debug(f"supported incoming request of type: {ssh_request_mtype}")
                return ssh_request_mtype
            logger.warning(f"unsupported request recieved of type: {ssh_request_mtype}, full data: {data}")
            return SSH_Messages.INVALID
    except ValueError as ve:
        print(f"Maybe connecting via socat, first 4 bytes are non-int: {data}")
        return SSH_Messages.DEFAULT
    logger.debug("was not able to recognise message type")
    return SSH_Messages.INVALID
