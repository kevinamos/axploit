import binascii

from .slices import slice_by_size

__author__ = 'netanelrevah'


def format_byte(byte):
    return binascii.hexlify(byte[:1]).decode('ascii')


def format_dword(dword):
    return ' '.join(slice_by_size(binascii.hexlify(dword).decode('ascii'), 2))


def hex_dump(data):
    data = bytes(data)
    max_digits_for_index = len(str(len(data)))
    indexes_format = "{:" + str(max_digits_for_index) + "}: "

    dwords = []
    for i in range(0, len(data), 8):
        dword = data[i: i + 8]
        dwords.append(indexes_format.format(i) + format_dword(dword))

    lines = []
    for i in range(0, len(dwords), 2):
        line = dwords[i]
        line += ' ' + dwords[i + 1] if i + 1 < len(dwords) else ''
        lines.append(line)

    return '\n'.join(lines)


def to_string_hex(value):
    return binascii.hexlify(value).decode('ascii')
