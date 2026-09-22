import logging

from .types import SSH_Messages


logger = logging.getLogger(__name__)


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
            message_type: bytes = data[4]
            logger.debug(f"message type: {message_type}")
            contents = data[5:]
            if message_type == SSH_Messages.SSH_AGENTC_REQUEST_IDENTITIES.value:
                logger.debug("listing number of identities attached")
                return SSH_Messages.SSH_AGENTC_REQUEST_IDENTITIES
    except ValueError as ve:
        print(f"Maybe connecting via socat, first 4 bytes are non-int: {data}")
        return SSH_Messages.DEFAULT
    logger.debug("was not able to recognise message type")
    return SSH_Messages.DEFAULT
