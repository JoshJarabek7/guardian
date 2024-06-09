import logging


class Hisss(logging.Logger):
    def __init__(self, name="hiss", level=logging.DEBUG, format=None, stream=None):
        super().__init__(name, level)
        if format is None:
            format = logging.Formatter(
                "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
            )
        if stream is None:
            stream = logging.StreamHandler()
        stream.setFormatter(format)
        self.addHandler(stream)

    def hiss(self, msg, level):
        if level == logging.INFO:
            self.info(msg=msg)
        elif level == logging.DEBUG:
            self.debug(msg=msg)
        elif level == logging.CRITICAL:
            self.critical(msg=msg)
        elif level == logging.ERROR:
            self.error(msg=msg)
        elif level == logging.FATAL:
            self.fatal(msg=msg)
