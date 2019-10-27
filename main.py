#!/usr/bin/python

## usage: main.py van_bin msm_bin .config_vanilla

import json
import r2pipe
import os
import sys
import re
import argparse

from StructDevice import process_StructDevice, init_struct_device
from StructFile import process_StructFile, init_struct_file
from OptionList import OptionList
from AnswerList import AnswerList   
from utils import *

Msm_oplist = None
Van_oplist = None
Msm_r2 = None
Van_r2 = None

# any struct can work
def search_ops_in_config(fname):
    if Van_oplist == None:
        print("Error: Vanilla Oplist not initialized.")
        exit()
    print("detected vanilla kernel .config file {}".format(fname))
    oplist_str = [x.name for x in Van_oplist.ops]
    # first clear all
    for op in Van_oplist.ops:
        Van_oplist.set_option(op.name, False)
    with open(fname) as f:
        for line in f.readlines():
            for item in oplist_str:
                if item+"=" in  line:
                    print("Vanilla Kernel: {} exists".format(item))
                    Van_oplist.set_option(item,force=True)

def parse_args():
    global Msm_r2
    global Van_r2

    parser = argparse.ArgumentParser(description='Current msm kernel commit: 83789a7935f9. Please ensure vanilla kernel has i2c support.')
    parser.add_argument('van', help='An integer for the accumulator')
    parser.add_argument('msm', help='An integer for the accumulator')
    parser.add_argument('cfg', help='.config file of vanilla kernel. Can be ignored.', nargs='?', default='')
    parser.add_argument('-v', '--verbose', help='Allow verbose output of each offset difference in the results.', action='store_true')
    parser.add_argument('-c', '--count', help='Maximum output count.', type=int, default=5)
    parser.add_argument('-t', '--threshold', help='Maximum offset difference allowed.', type=int, default=0)
    args = parser.parse_args()

    print("reading target files...")
    if args.cfg != '':
        search_ops_in_config(args.cfg)
    Msm_r2 = r2pipe.open(sys.argv[2])
    Van_r2 = r2pipe.open(sys.argv[1])
    if(Msm_r2==None):
        print("Error: msm kernel read failed.")
        exit()
    if(Van_r2==None):
        print("Error: vanilla kernel read failed.")
        exit()
    ver = use_version(Msm_r2)
    print("detected r2 version: {}".format(ver))
    AnswerList.Verbose = args.verbose
    AnswerList.Threshold = args.threshold
    AnswerList.Maxcount = args.count

def init():
    global Msm_oplist
    global Van_oplist
    anls = AnswerList("msm", "vanilla")
    Msm_oplist = OptionList("msm", anls)
    Van_oplist = OptionList("vanilla", anls)
    init_struct_device(Msm_oplist, Van_oplist)
    init_struct_file(Msm_oplist, Van_oplist)
    parse_args()

    print("=================================================")
    print("reading files successful.")
    print("processing...")

if __name__ == "__main__":
    init()
    process_StructDevice(Msm_r2, Van_r2)
    process_StructFile(Msm_r2, Van_r2)
    Msm_oplist.calc_options(Van_oplist)
