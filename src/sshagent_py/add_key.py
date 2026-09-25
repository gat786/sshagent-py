from .message import parse_eddsa_key

def add_key(data: bytes):
    parsed_eddsa_key = parse_eddsa_key(data=data)
    breakpoint()
    pass
