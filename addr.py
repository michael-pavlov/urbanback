# This class represents an IPv4 address. It stores it as an unsigned integer, the size of which is
# implied to be 32 bit.
class Address:
    def __init__(self, u32):
        self.u32 = u32

    def __str__(self):
        segments = [(self.u32 >> shift) & 0xFF for shift in range(0, 32, 8)]
        return '.'.join(str(segment) for segment in reversed(segments))

    # Parse an address from string of format "X.Y.Z.W", where X, Y, Z, W are
    # one-byte values written in decimal.
    @staticmethod
    def parse(s):
        u32 = 0
        for segment in s.split('.'):
            u32 <<= 8
            u32 |= int(segment)
        return Address(u32)

    def __eq__(self, other):
        if not isinstance(other, Address):
            return False
        return self.u32 == other.u32

    def __ne__(self, other):
        if not isinstance(other, Address):
            return True
        return self.u32 != other.u32

    def __hash__(self):
        return hash(self.u32)


# This class represents a IPv4 subnetwork, defined by the base address and mask.
class Subnet:
    def __init__(self, base, mask):
        self.base = base
        self.mask = mask

    def __contains__(self, addr):
        return (addr.u32 & self.mask.u32) == self.base.u32
