import logging


# TODO: move to logging configuration file
def init_logger() -> logging.Logger:
    default_log_file_path: str = '/tmp/trace.log'
    logging_format: str = "%(asctime)s %(name)16s [%(levelname)-8s] %(message)s"

    logging.basicConfig(level=logging.DEBUG,
                        format=logging_format)
    logging.getLogger("pika").setLevel(logging.DEBUG)

    file_handler: logging.Handler = logging.FileHandler(default_log_file_path)
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(logging.Formatter(logging_format))

    log: logging.Logger = logging.getLogger(__file__)
    log.addHandler(file_handler)

    return log


if __name__ == '__main__':
    logger = init_logger()

    logger.debug('debug message')
    logger.debug(__name__)
    logger.info('info message')
    logger.warning('warn message')
    logger.error('error message')
    logger.critical('critical message')
