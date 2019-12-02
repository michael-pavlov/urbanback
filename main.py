#!/usr/bin/env python3
# version 1.4
import os
import time
import json
import bottle
from sklearn.cluster import OPTICS
from addr import Address, Subnet
from clusterize import clusterize
from bottle import response

ALGO = OPTICS(min_samples=4)


# Dataset 'rotation' period, in seconds.
PERIOD = 20


OUR_SUBNET = Subnet(
    base=Address.parse('192.168.100.0'),
    mask=Address.parse('255.255.255.0'))


OUR_DMZ = Address.parse('5.227.94.15')


# Dataset properties.
NFILES, FILENAME_PATTERN = 10, 'data_{index}.csv'


def is_our_address(addr):
    return addr in OUR_SUBNET or addr == OUR_DMZ


global_clusters = None
global_timestamp = -1
global_index = 0


# Increments the global file index by `index_delta`, reads the file, clusterizes it and updates the
# appropriate global variables.
def update_global_data(index_delta):
    global global_clusters
    global global_timestamp
    global global_index

    global_index += index_delta
    global_index %= NFILES

    global_clusters = clusterize(
        FILENAME_PATTERN.format(index=global_index),
        algo=ALGO)
    global_timestamp = time.monotonic()


# If needed, reads the file and clusterizes it. Returns `(clusters, epoch)` tuple, where clusters
# is a 'Clusters' object and `epoch` is an integer specifying which dataset is used.
def get_global_data():
    global global_clusters
    global global_timestamp
    global global_index

    if global_clusters is None:
        update_global_data(index_delta=0)
    else:
        delta = time.monotonic() - global_timestamp
        index_delta = int(delta / PERIOD)
        if index_delta > 0:
            update_global_data(index_delta=index_delta)

    return global_clusters, global_index


def serve_json(obj):
    return json.dumps(obj)


@bottle.get('/get-attacks')
def get_clusters():
    data, epoch = get_global_data()

    result = {}
    for key, indices in data.classes.items():
        level = max(data.attacks[i].level for i in indices)
        result[str(key)] = level
    return serve_json({'result': result, 'epoch': epoch})


@bottle.get('/get-attack/<key:int>')
def get_cluster(key):
    data, epoch = get_global_data()

    indices = data.classes[key]
    result = []
    for i in indices:
        attack = data.attacks[i]
        if not is_our_address(attack.dest_addr):
            continue
        result.append({
            'from': str(attack.source_addr),
            'to': str(attack.dest_addr),
            'level': attack.level,
        })
    return serve_json({'result': result, 'epoch': epoch})


def main():
    response.headers['Access-Control-Allow-Origin'] = '*'
    bottle.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))

if __name__ == '__main__':
    main()
