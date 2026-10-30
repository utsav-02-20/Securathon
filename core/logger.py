import logging
import sys
from typing import Optional


def setup_logger(name: str = "securathon", level: Optional[str] = None) -> logging.Logger:
    """
    Configures and returns a structured logger with standard formatting.
    """
    logger = logging.getLogger(name)
    
    if not logger.handlers:
        log_level_str = (level or "INFO").upper()
        log_level = getattr(logging, log_level_str, logging.INFO)
        logger.setLevel(log_level)

        handler = logging.StreamHandler(sys.stdout)
        handler.setLevel(log_level)

        formatter = logging.Formatter(
            fmt="%(asctime)s [%(levelname)s] [%(name)s] %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S"
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)

    return logger

