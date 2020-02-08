#!/usr/bin/python
#import fiwalk
import time
import os
import sys
sys.path.append( os.path.join(os.path.dirname(__file__), ".."))
import dfxml
import json
import argparse
import ast
import pandas as pd
import numpy as np
import math
pd.set_option('display.max_colwidth', -1)
from time import clock
from time import time, strftime, localtime
from datetime import timedelta

def _make_parser():
    parser = argparse.ArgumentParser( description='This script takes the app dfxml and scan it against sector hashes of a target image (csv), outputing a csv file with columns {blocks:a_fileoffset:a_filehash:a_filepath:t_alloc:t_file_hash:t_filepath:consq_matches}')
    parser.add_argument("json", help="JSON file to read")
    parser.add_argument("imgcsv", help="IMG CSV file to read")
    parser.add_argument("remcsv", help="remnant CSV list of unprocessed file hashes")
    parser.add_argument("csv", help="CSV file to output result to")
    parser.add_argument("array1toNfiles", help="ARGO array_index (e.g. 1 to n files for n app files) hash to scan the image with the file blocks")
    return parser

def compare(file_series, imgcsv_df):
    counter = 0
    file_out_df = pd.DataFrame()

    file_series = file_series.reset_index(drop=True)

    for file_block_i in range(0,len(file_series)-1):#file_series:#file_series:#len(file_series.index))
        #file_block = file_series[file_block_index]
        block_hash = file_series[file_block_i]
        #print("block_hash",block_hash)
        next_block_hash = file_series[file_block_i + 1]
        block_match_pair_s = pd.Series()
        file_out_df.loc[file_block_i,"block_hash"] = block_hash
        file_out_df.loc[file_block_i,"file_offset"] = file_block_i
        file_out_df.loc[file_block_i,"file_hash"] = file_series.name
        matched_img_list = imgcsv_df[imgcsv_df["cluster_hash"] == block_hash].index.tolist()
        #print("matched_img_list",matched_img_list)
        for img_index in matched_img_list:
            if (int(img_index+1) in imgcsv_df.index) and (next_block_hash == imgcsv_df.loc[img_index+1,"cluster_hash"]):
                block_match_pair_s = block_match_pair_s.append(pd.Series([img_index]))
        #the presence of the last member of the block_match_pairs_s imply the next index should be included
        #block_match_pair_s = block_match_pair_s.append(pd.Series([block_match_pair_s.iloc[-1]]))
        file_out_df.loc[file_block_i,"matched_pairs"] = str(block_match_pair_s.tolist())

    for file_block_i in range(len(file_series)-1,len(file_series)):  # file_series:#file_series:#len(file_series.index))
        # file_block = file_series[file_block_index]
        block_hash = file_series[file_block_i]
        #print("block_hash", block_hash)
        previous_block_hash = file_series[file_block_i - 1]
        block_match_pair_s = pd.Series()
        file_out_df.loc[file_block_i, "block_hash"] = block_hash
        file_out_df.loc[file_block_i, "file_offset"] = file_block_i
        file_out_df.loc[file_block_i, "file_hash"] = file_series.name
        matched_img_list = imgcsv_df[imgcsv_df["cluster_hash"] == block_hash].index.tolist()
        #print("matched_img_list", matched_img_list)
        for img_index in matched_img_list:
            if (int(img_index - 1) in imgcsv_df.index) and (previous_block_hash == imgcsv_df.loc[img_index - 1, "cluster_hash"]):
                block_match_pair_s = block_match_pair_s.append(pd.Series([img_index]))
        # the presence of the last member of the block_match_pairs_s imply the next index should be included
        # block_match_pair_s = block_match_pair_s.append(pd.Series([block_match_pair_s.iloc[-1]]))
        file_out_df.loc[file_block_i, "matched_pairs"] = str(block_match_pair_s.tolist())

    #print(file_out_df.head(5))
    file_out_df.to_csv(args.csv+file_series.name+".csv")


if __name__=="__main__":
    parser = _make_parser()
    args = parser.parse_args()
    start = time()
    imgcsv = pd.read_csv(args.imgcsv)
    with open(args.json, 'r') as json1:
        input_json = (line.strip() for line in json1)
        data_json = "[{0}]".format(','.join(input_json))
    app = pd.read_json(data_json)

    files = app.dropna(subset=["file_hash"])
    files = files["file_hash"]
    files = files.reset_index(drop=True)

    blocks = app.dropna(subset=["block_hash"])
    blocks["file_hash"] = blocks["source_sub_counts"].str[0]
    blocks = blocks[["block_hash","file_hash"]]

    #for index,value in files.items():
    fileseries = pd.read_csv(args.remcsv, header=None, usecols=[1], names = ['file_hash'])
    #print("fileseries")
    #print(fileseries)

    file_hash = fileseries.loc[(int(args.array1toNfiles)-1), 'file_hash']
    file_df = blocks[blocks["file_hash"]==file_hash]
    file_series = file_df["block_hash"]
    file_series.name = file_hash
    compare(file_series,imgcsv)
