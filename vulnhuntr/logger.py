import logging

logger = logging.getLogger("xvulnhuntr")

def configure_logger(verbosity: int):
    level = logging.DEBUG if verbosity > 0 else logging.INFO
    logger.setLevel(level)

    if logger.hasHandlers():
        logger.handlers.clear()

    console_handler = logging.StreamHandler()
    console_handler.setLevel(level)

    formatter = logging.Formatter("%(message)s")
    console_handler.setFormatter(formatter)

    logger.addHandler(console_handler)

    # Suppress logs from external libraries
    logging.getLogger().setLevel(logging.WARNING)
