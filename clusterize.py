from batch import read_csv, Batch
from cluster_builder import ClusterBuilder


# This class represents a result of clusterization. `attacks` is a list of 'Attack' values, and
# `classes` is a dictionary of form `{class_ID: indices}`.
class Clusters:
    def __init__(self, attacks, classes):
        self.attacks = attacks
        self.classes = classes


# Perform clustering on the CSV file with path 'path', using sklearn.cluster algorithm 'algo'.
# Returns a 'Clusters' object.
def clusterize(path, algo):
    attacks = list(read_csv(path))

    cluster_builder = ClusterBuilder(nitems=len(attacks))

    batch = Batch()
    addr_to_index = {}
    for index, attack in enumerate(attacks):
        batch.feed(attack)
        addr = attack.source_addr
        try:
            prev_index = addr_to_index[addr]
        except KeyError:
            pass
        else:
            cluster_builder.merge(prev_index, index)
        addr_to_index[addr] = index

    db = algo.fit([batch.features(attack) for attack in attacks])

    specimen = [-1 for _ in range(len(set(db.labels_)))]

    for index, attack in enumerate(attacks):
        cluster = db.labels_[index]
        if cluster == -1:
            cluster_builder.mark_as_noise(index)
            continue
        if specimen[cluster] != -1:
            cluster_builder.merge(specimen[cluster], index)
        specimen[cluster] = index

    return Clusters(attacks=attacks, classes=cluster_builder.finalize())
