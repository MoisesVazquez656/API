import logging
import os

LOG_DIR = "logs"
LOG_FILE = os.path.join(LOG_DIR, "app.log")

if not os.path.exists(LOG_DIR):
    os.makedirs(LOG_DIR)

logger = logging.getLogger("api_logger")
logger.setLevel(logging.DEBUG)

if not logger.handlers:
    file_handler = logging.FileHandler(LOG_FILE, encoding="utf-8")
    file_handler.setLevel(logging.DEBUG)

    formatter = logging.Formatter(
        "[%(asctime)s] | [%(levelname)s] | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )

    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)