import math
import csv
from addr import Address


# This class represents a line in the source CSV file.
class Attack:
    def __init__(self, timestamp, source_addr, dest_addr, incident_type, level):
        self.timestamp = timestamp
        self.source_addr = source_addr
        self.dest_addr = dest_addr
        self.incident_type = incident_type
        self.level = level


# Returns a generator that generates Attack values, corresponding to the lines in the file.
def read_csv(path):
    with open(path, 'r') as csv_file:
        for row in csv.reader(csv_file):
            yield Attack(
                timestamp=float(row[2]),
                source_addr=Address.parse(row[5]),
                dest_addr=Address.parse(row[6]),
                incident_type=float(row[9]),
                level=int(row[18])
            )


# Normalize an IPv4 address: just divide the unsigned integer representation by 2^32, so that
# addresses in the same subnetwork be close to each other.
def _normalize_addr(addr):
    return addr.u32 / (1 << 32)


# This class contains some meta-data about a 'batch', that is, a collection of samples (Attack
# values).
# First, it needs to be 'fed' all the values. After that, it can return the feature vector given an
# attack value.
class Batch:
    def __init__(self):
        self.min_timestamp = math.inf
        self.max_timestamp = -math.inf

    def feed(self, attack):
        self.min_timestamp = min(self.min_timestamp, attack.timestamp)
        self.max_timestamp = max(self.max_timestamp, attack.timestamp)

    def normalize_timestamp(self, timestamp):
        delta = self.max_timestamp - self.min_timestamp
        if delta == 0:
            return 0
        return (timestamp - self.min_timestamp) / delta

    def features(self, attack):
        return [
            self.normalize_timestamp(attack.timestamp),
            _normalize_addr(attack.source_addr),
            attack.incident_type / 10,
        ]
