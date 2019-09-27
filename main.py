#!/usr/bin/python

## usage: main.py van_bin msm_bin .config_vanilla

import json
import r2pipe
import os
import sys
import re
import argparse

from StructDevice import process_StructDevice
from StructFile import process_StructFile
from Structs import AnswerList
from utils import *


# any struct can work
def search_ops_in_config(fname):
    from StructDevice import Struct_vanilla
    struct = Struct_vanilla
    print("detected vanilla kernel .config file {}".format(fname))
    oplist_str = [x.name for x in struct.oplist.ops]
    # first clear all
    for op in struct.oplist.ops:
        struct.oplist.set_option(op.name, False)
    with open(fname) as f:
        for line in f.readlines():
            for item in oplist_str:
                if item+"=" in  line:
                    print("Vanilla Kernel: {} exists".format(item))
                    struct.oplist.set_option(item,force=True)

def parse_args():
    global Msm_r2
    global Van_r2
    parser = argparse.ArgumentParser(description='Current msm kernel commit: 83789a7935f9. Please ensure vanilla kernel has i2c support.')
    parser.add_argument('van', help='An integer for the accumulator')
    parser.add_argument('msm', help='An integer for the accumulator')
    parser.add_argument('cfg', help='.config file of vanilla kernel. Can be ignored.', default='')
    parser.add_argument('-v', '--verbose', help='Allow verbose output of each offset difference in the results.', action='store_true')
    parser.add_argument('-c', '--count', help='Maximum output count.', type=int, default=5)
    parser.add_argument('-t', '--threshold', help='Maximum offset difference allowed.', type=int, default=0)

    args = parser.parse_args()
    print("reading target files...")
    if args.cfg != '':
        search_ops_in_config(sys.argv[3])
    AnswerList.Verbose = args.verbose
    AnswerList.Threshold = args.threshold
    AnswerList.Maxcount = args.count
    Msm_r2 = r2pipe.open(sys.argv[2])
    Van_r2 = r2pipe.open(sys.argv[1])
    if(Msm_r2==None):
        print("Error: msm kernel read failed.")
        exit()
    if(Van_r2==None):
        print("Error: vanilla kernel read failed.")
        exit()
        

def init():
    parse_args()

    print("=================================================")
    print("reading files successful.")
    print("processing...")

if __name__ == "__main__":
    init()
    process_StructDevice(Msm_r2, Van_r2)
    process_StructFile(Msm_r2, Van_r2)
