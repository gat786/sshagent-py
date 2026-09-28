from .message import parse_eddsa_key
from .types import SSHCryptoKey


def get_parsed_key(data: bytes) -> SSHCryptoKey | None:
    """converts raw bytes to SSHCryptoKey Dataclass

    Function should automatically detect the type of key from the bytes
    representation, pass it to the parser function and return appropriate data
    class
    """
    try:
        parsed_eddsa_key = parse_eddsa_key(data=data)
        return parsed_eddsa_key
    except UnicodeDecodeError:
        return None
