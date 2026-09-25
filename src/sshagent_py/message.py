import logging

from .types import (
    SSH_Messages,
    supported_incoming_messages,
    SshRequest,
    EDDsaKey
)

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

def parse_ssh_request(data: bytes) -> SshRequest:
    request_size = data[:4]
    request_size = int.from_bytes(request_size, byteorder="big")
    request_method = int.from_bytes(data[4:5])
    data = data[5:]
    return SshRequest(
        size_of_request=request_size,
        request_method=request_method,
        request_body=data
    )

def parse_eddsa_key(data: bytes) -> EDDsaKey:
    # implementation for eddsa key
    key_name_size = data[:4]
    key_name_size = int.from_bytes(key_name_size, byteorder="big")
    key_name = bytes.decode(
        data[ 4 : 4 + key_name_size],
        encoding="utf-8"
    )

    public_key_size = data[(4 + key_name_size):((4 + key_name_size) + 4)]
    public_key_size = int.from_bytes(public_key_size, byteorder="big")
    pub_k_starts_from = (4 + key_name_size) + 4
    public_key_content = data[
        pub_k_starts_from:
            pub_k_starts_from + public_key_size
    ]
    breakpoint()
    private_key_size = data[
        pub_k_starts_from + public_key_size
        : (pub_k_starts_from + public_key_size) + 4
    ]
    private_key_size = int.from_bytes(private_key_size, byteorder="big")
    pr_k_starts_from = (pub_k_starts_from + public_key_size) + 4
    private_key_content = data[
        pr_k_starts_from :
            pr_k_starts_from+private_key_size
    ]
    private_seed_only = private_key_content[:32]

    comment_size = data[
        pr_k_starts_from + private_key_size :
            (pr_k_starts_from + private_key_size) + 4
    ]
    comment_size = int.from_bytes(comment_size, byteorder="big")
    comment_starts_from = (pr_k_starts_from + private_key_size) + 4
    comment_content = bytes.decode(data[
        comment_starts_from :
            comment_starts_from + comment_size
    ], encoding="utf-8")

    return EDDsaKey(
        type=key_name,
        public_key=public_key_content,
        private_seed=private_seed_only,
        private_seed_and_public_key=private_key_content,
        comment=comment_content
    )

def parse_rsa_key() -> None:
    pass

def parse_ecdsa_key() -> None:
    pass

def parse_dsa_key() -> None:
    pass
