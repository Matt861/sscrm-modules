from datetime import datetime

class Timer:
    def __init__(self):
        self.start_time = None
        self.end_time = None

    def start(self, start_message):
        print(start_message)
        self.start_time = datetime.now()
        self.end_time = None

    def stop(self, stop_message):
        print(stop_message)
        self.end_time = datetime.now()

    def elapsed(self, elapsed_message):
        if self.start_time is None:
            return "Timer has not been started."
        if self.end_time is None:
            return "Timer has not been stopped."
        elapsed_time = self.end_time - self.start_time
        return f"{elapsed_message} {elapsed_time}"