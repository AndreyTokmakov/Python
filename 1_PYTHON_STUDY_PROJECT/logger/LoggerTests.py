import logging

LOG_FILE_NAME = "/tmp/trace.log"


def TetLogs_TwoHandlers():
    logger = logging.getLogger("Logger")
    logger.setLevel(logging.DEBUG)

    logFileformatter = logging.Formatter('%(asctime)s - %(name)s - [%(levelname)-8s] : %(message)s')
    streamformatter = logging.Formatter('[%(levelname)-8s] : %(message)s')

    handler = logging.FileHandler(LOG_FILE_NAME)
    handler.setLevel(logging.DEBUG)
    handler.setFormatter(logFileformatter)

    streamHandler = logging.StreamHandler()
    streamHandler.setLevel(logging.INFO)
    streamHandler.setFormatter(streamformatter)

    logger.addHandler(handler)
    logger.addHandler(streamHandler)

    logger.debug('debug message')
    logger.debug(__name__)
    logger.info('info message')
    logger.warning('warn message')
    logger.error('error message')
    logger.critical('critical message')


def TestLogs2():
    logger = logging.getLogger(__name__)
    logger.setLevel(logging.INFO)

    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')

    handler = logging.FileHandler(LOG_FILE_NAME)
    handler.setLevel(logging.INFO)
    handler.setFormatter(formatter)

    logger.addHandler(handler)
    logger.info('Hello baby')


if __name__ == '__main__':
    TetLogs_TwoHandlers()
    # TestLogs2();
