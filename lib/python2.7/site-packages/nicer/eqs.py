class ComparableMixin(object):
    def __eq__(self, other):
        return self.to_comparable() == other.to_comparable()

    def to_comparable(self):
        raise NotImplementedError()
