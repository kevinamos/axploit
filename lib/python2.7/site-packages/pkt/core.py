from nicer.bits import hex_dump, to_string_hex
from nicer.eqs import ComparableMixin

__author__ = 'netanelrevah'


class Packet(ComparableMixin):
    def __init__(self, data):
        self.data = data

    def __len__(self):
        return len(self.data)

    def __repr__(self):
        return '<Packet - %d bytes>' % (len(self))

    def __str__(self):
        return to_string_hex(self.data)

    def __iter__(self):
        return iter(self.data)

    def __getitem__(self, item):
        return self.data.__getitem__(item)

    def hex_dump(self):
        return hex_dump(self.data)

    def to_comparable(self):
        return self.data
