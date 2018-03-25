__author__ = 'netanelrevah'


def slice_by_size(slice_able, size):
    return [slice_able[l:l+size] for l in range(0, len(slice_able), size)]