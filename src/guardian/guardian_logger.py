import logging

class GuardianLogger(logging.Logger):
    def __init__(self, name, level=logging.NOTSET):
        super().__init__(name, level)
        self.extra_info = None
    
    def info(self, msg, *args, xtra=None, **kwargs):
        extra_info = xtra if xtra is not None else self.extra_info
        super().info(msg, *args, extra=extra_info, *kwargs)

guardian_logger = GuardianLogger()