import logging


def setup_logging():
    """Initialize basic logging."""
    logging.basicConfig(
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        level=logging.INFO,
    )


def get_logger(name: str):
    """Get a logger instance."""
    return logging.getLogger(name)
