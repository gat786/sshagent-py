import logging
import os

from . import listener

log_level = os.getenv("SSH_AGENT_LOGLEVEL", "INFO")

logging.basicConfig(
    format="%(asctime)s - %(filename)s:%(funcName)s:%(lineno)s - %(levelname)s - %(threadName)s - %(message)s",
    level=logging.getLevelNamesMapping()[log_level],
)


def main() -> None:
    logger = logging.getLogger(__name__)
    logger.info("Starting up listeners...")
    listener.setup_listener()
