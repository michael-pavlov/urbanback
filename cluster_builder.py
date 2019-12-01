# A cluster builder is a slightly modified union-find data structure (see
# https://en.wikipedia.org/wiki/Disjoint-set_data_structure): aside from find()/merge() operations,
# it supports marking elements as "noise" that should be just filtered out.
class ClusterBuilder:
    # Create a new union-find data structure with `nitems` elements, each in its own class.
    def __init__(self, nitems):
        self.roots = [i for i in range(nitems)]
        self.ranks = [0 for _ in range(nitems)]
        self.noise = [False for _ in range(nitems)]

    # Get class ID of element with index `i`.
    def find(self, i):
        while self.roots[i] != i:
            j = self.roots[i]
            self.roots[i] = j
            i = j
        return i

    # Merge classes of elements with indices `i` and `j`.
    def merge(self, i, j):
        i = self.find(i)
        j = self.find(j)
        if i == j:
            return
        if self.ranks[i] < self.ranks[j]:
            i, j = j, i
        self.roots[j] = i
        if self.ranks[i] == self.ranks[j]:
            self.ranks[i] += 1

    # Mark the element with index `i` as "noise".
    def mark_as_noise(self, i):
        self.noise[i] = True

    # Returns a `{class_ID: element_list}` dictionary, filtering out the "noise".
    def finalize(self):
        result = {}
        for index in range(len(self.roots)):
            if self.noise[index]:
                continue
            root = self.find(index)
            try:
                result[root].append(index)
            except KeyError:
                result[root] = [index]
        return result
