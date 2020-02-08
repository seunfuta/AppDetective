'''
Usage: python convert_img2clusters.py IMG/app.img IMGCSV/app.csv
Description: gets all the 4096 bytes size sectors/clusters in an image and save cluster_pos, cluster_hash in a csv file.
'''

import hashlib
import os
import sys
import pprint
import sqlite3
from datetime import datetime
from xml.etree import ElementTree
import xml.etree.cElementTree as ET
import math
import csv
import re
import json



if __name__ == "__main__":
    startTime = datetime.now()
    img_size = os.path.getsize(sys.argv[1])
    num_of_cluster = int(math.ceil(float(img_size) / float(512)))
    with open(sys.argv[2], 'w+') as fileh:
        csv_writer = csv.writer(fileh, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
        csv_writer.writerow(["cluster_pos", "cluster_hash"])
        with open(sys.argv[1], 'rb') as fopen:  # dict[dfxml]
            pos = 0
            for sector_index in range(0, num_of_cluster):
                #pos = int(image_offset) + int(fileoffset) + (sector_index * 4096)
                #m_fileoffset = int(fileoffset) + (sector_index * 4096)
                fopen.seek(pos)
                fsector = fopen.read(512)
                cluster_hash = hashlib.md5(fsector).hexdigest()
                csv_writer.writerow([pos, cluster_hash])
                pos += 512
    sys.exit()