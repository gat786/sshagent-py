from dataclasses import dataclass
from enum import IntEnum
from typing import Literal, List


class SSH_Messages(IntEnum):
    INVALID = -1
    DEFAULT = 0

    SSH_AGENT_FAILURE = 5
    SSH_AGENT_SUCCESS = 6

    SSH_AGENTC_REQUEST_IDENTITIES = 11
    SSH_AGENT_IDENTITIES_ANSWER = 12

    SSH_AGENTC_SIGN_REQUEST = 13
    SSH_AGENT_SIGN_RESPONSE = 14

    SSH_AGENTC_ADD_IDENTITY = 17
    SSH_AGENTC_REMOVE_IDENTITY = 18

    SSH_AGENTC_REMOVE_ALL_IDENTITIES = 19
    SSH_AGENTC_ADD_SMARTCARD_KEY = 20
    SSH_AGENTC_REMOVE_SMARTCARD_KEY = 21
    SSH_AGENTC_LOCK = 22
    SSH_AGENTC_UNLOCK = 23
    SSH_AGENTC_ADD_ID_CONSTRAINED = 25
    SSH_AGENTC_ADD_SMARTCARD_KEY_CONSTRAINED = 26
    SSH_AGENTC_EXTENSION = 27

    SSH_AGENT_EXTENSION_FAILURE = 28
    SSH_AGENT_EXTENSION_RESPONSE = 29

supported_incoming_messages = [
    SSH_Messages.SSH_AGENTC_REQUEST_IDENTITIES,
    SSH_Messages.SSH_AGENTC_ADD_IDENTITY,
    SSH_Messages.SSH_AGENTC_ADD_ID_CONSTRAINED,
    SSH_Messages.SSH_AGENTC_REMOVE_IDENTITY,
    SSH_Messages.SSH_AGENTC_REMOVE_ALL_IDENTITIES,
    SSH_Messages.SSH_AGENTC_SIGN_REQUEST,
    SSH_Messages.SSH_AGENTC_ADD_SMARTCARD_KEY,
    SSH_Messages.SSH_AGENTC_REMOVE_SMARTCARD_KEY,
    SSH_Messages.SSH_AGENTC_LOCK,
    SSH_Messages.SSH_AGENTC_UNLOCK,
    SSH_Messages.SSH_AGENTC_ADD_ID_CONSTRAINED,
    SSH_Messages.SSH_AGENTC_ADD_SMARTCARD_KEY_CONSTRAINED,
    SSH_Messages.SSH_AGENTC_EXTENSION
]

valid_response_messages = [
    SSH_Messages.SSH_AGENT_FAILURE,
    SSH_Messages.SSH_AGENT_SUCCESS,
    SSH_Messages.SSH_AGENT_IDENTITIES_ANSWER,
    SSH_Messages.SSH_AGENT_SIGN_RESPONSE,
    SSH_Messages.SSH_AGENT_EXTENSION_FAILURE,
    SSH_Messages.SSH_AGENT_EXTENSION_RESPONSE
]

@dataclass
class SshRequest():
    # this will change according to the request contents
    size_of_request: int
    # this should be equal to the IntEnum value we have above
    request_method: int
    # we will have to format this according to different specifications
    # depending on the size and method mentioned above.
    request_body: bytes

@dataclass
class SSHKeyLifetimeConstraint:
    seconds: int

@dataclass
class SSHKeyConfirmationConstraint:
    confirm: bool = False

@dataclass
class EDDsaKey():
    comment: str
    public_key: bytes
    private_seed_and_public_key: bytes
    private_seed: bytes
    # Literal["ssh-ed25519", "ssh-ed448"]
    type: str = "ssh-ed25519"

    # constraints: List = []

@dataclass
class ECDsaKey():
    pass

@dataclass
class DsaKey():
    type: str
