from loguru import logger


def debug(message, *args, **kwargs):
    logger.opt(depth=1).debug(message, *args, **kwargs)
