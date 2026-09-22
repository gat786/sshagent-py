import logging
import os

from . import listener


logging.basicConfig(
    format="%(asctime)s - %(filename)s:%(funcName)s:%(lineno)s - %(levelname)s - %(threadName)s - %(message)s",
    level=logging.DEBUG,
)


def main() -> None:
    logger = logging.getLogger(__name__)
    logger.info("Starting up listeners...")
    listener.setup_listener()
