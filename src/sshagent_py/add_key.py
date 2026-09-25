from .message import parse_eddsa_key
from .types import SSHCryptoKey


def get_parsed_key(data: bytes) -> SSHCryptoKey:
    parsed_eddsa_key = parse_eddsa_key(data=data)
    return parsed_eddsa_key
