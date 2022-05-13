import pyshark
import time

class Timer:
    def __init__(self, func=time.perf_counter):
        self.elapsed = 0.0
        self._func = func
        self._start = None

    def start(self):
        if self._start is not None:
            raise RuntimeError('Already started')
        self._start = self._func()

    def stop(self):
        if self._start is None:
            raise RuntimeError('Not started')
        end = self._func()
        self.elapsed += end - self._start
        self._start = None

    def reset(self):
        self.elapsed = 0.0

    @property
    def running(self):
        return self._start is not None

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, *args):
        self.stop()


cap = pyshark.FileCapture('../../../../pcap/ICS/modbus/modbus.pcap')

t = Timer()
t.start()

while True:
    try:
        cap.next()
    except StopIteration:
        t.stop()
        print('{:.2f} ms'.format(t.elapsed * 1000))
        break
