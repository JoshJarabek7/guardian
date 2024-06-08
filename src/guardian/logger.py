import logging


class GuardianLogger(logging.Logger):
    def __init__(self, name="guardian", level=logging.DEBUG, format=None, stream=None):
        super().__init__(name, level)
        if format is None:
            format = logging.Formatter(
                "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
            )
        if stream is None:
            stream = logging.StreamHandler()
        stream.setFormatter(format)
        self.addHandler(stream)
