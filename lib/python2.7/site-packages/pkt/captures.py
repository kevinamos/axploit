import datetime

from nicer.eqs import ComparableMixin
from nicer.times import Timestamp
from . import Packet

__author__ = 'netanelrevah'


class CapturedPacket(Packet):
    def __init__(self, data, capture_time=None, original_length=None):
        super(CapturedPacket, self).__init__(data)
        self.capture_time = self._normalize_capture_time(capture_time)
        self.original_length = self._normalize_original_length(original_length, len(data))

    @staticmethod
    def _normalize_capture_time(capture_time=None):
        if capture_time is None:
            return Timestamp.now()
        if isinstance(capture_time, Timestamp):
            return capture_time
        if isinstance(capture_time, datetime.datetime):
            return Timestamp.from_datetime(capture_time)
        if isinstance(capture_time, int) or isinstance(capture_time, float):
            return Timestamp.from_timestamp(capture_time)
        raise TypeError('capture_time must be timestamp (int or float), datetime.datetime or None (for current_time)')

    @staticmethod
    def _normalize_original_length(original_length, data_length):
        if original_length:
            return original_length
        return data_length

    def copy(self):
        return CapturedPacket(self.data, self.capture_time, self.original_length)

    @property
    def is_fully_captured(self):
        return self.original_length == len(self)

    def __repr__(self):
        return '<CapturedPacket - %d bytes captured at %s >' % (len(self.data), self.capture_time)

    def to_comparable(self):
        return self.data, self.capture_time, self.original_length


class CaptureEnvironment(object):
    pass


class NetworkCapture(ComparableMixin):
    def __init__(self, captured_packets=None, environment=None):
        self.captured_packets = captured_packets if captured_packets is not None else []
        self.environment = environment

    def to_comparable(self):
        return self.captured_packets, self.environment

    def __len__(self):
        return len(self.captured_packets)

    def __iter__(self):
        return self.captured_packets.__iter__()

    def __repr__(self):
        if len(self) == 0:
            return '<NetworkCapture - Empty>'
        return '<NetworkCapture - {0} packets>'.format(len(self))

    def __getitem__(self, index):
        return self.captured_packets[index]

    def append(self, packet):
        self.captured_packets.append(packet)
