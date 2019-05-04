#!/usr/bin/python

## usage: main.py van_bin msm_bin

import json
import r2pipe
import os
import sys
import re

from StructDevice import StructDevice
from Basicblock import Basicblock

Struct_vanilla = StructDevice("vanilla")
Struct_msm = StructDevice("msm")

def static_vars(**kwargs):
    def inner_func(func):
        for k in kwargs:
            setattr(func,k,kwargs[k])
        return func
    return inner_func

class FuncList:
    def __init__(self,FuncTar,FuncTarSubs):
        self.FuncTar = FuncTar
        self.FuncTarSubs = FuncTarSubs

def anal_tar_func(r2, r2_id, funclist):
    FuncTar = funclist.FuncTar
    FuncTarSubs = funclist.FuncTarSubs
    print("analyzing target function in {}...".format(r2_id))
    ret = r2.cmd("fs symbols;f~"+FuncTar).strip()
    if len(ret)<=2:
        print(r2_id+" doesn't have function "+FuncTar)
        exit();
    r2.cmd("af @ {}".format(FuncTar))
    for rgs in FuncTarSubs:
        for item in rgs:
            ret = r2.cmd("fs symbols;f~"+item).strip()
            if len(ret)<=2:
                print(r2_id+" doesn't have function "+item)
                exit();
            r2.cmd("af @ {}".format(item))


def get_search_range_i2c_0(r2, r2_id,funclist):
    FuncTar = funclist.FuncTar
    FuncTarSubs = funclist.FuncTarSubs
    print("searching for xrefs in {}...".format(r2_id))
    ret = []
    ret = r2.cmd("afij {}".format(FuncTar)).strip()
    ret = json.loads(ret)
    start = ret[0]["offset"]
    end = ret[0]["offset"]+ret[0]["size"]

    range_str="e search.in=raw; e search.from={}; e search.to={};".format(start,end)
    esil_str = lambda s : range_str+"/cej pc,lr,=,{},pc,=".format(s)
    
    fret = []
    for pairs in FuncTarSubs:
        tar_addr = []
        for item in pairs:
            ret = r2.cmd("afij "+item).strip()
            if len(ret)<=2:
                print("reading {} info failed".format(item))
                exit()
            ret = json.loads(ret)
            
            ret = r2.cmd(esil_str(ret[0]['offset'])).strip()
            if len(ret)<=2:
                print("no esil found, esil: {}".format(esil_str(off)))
                exit()
            ret = json.loads(ret)
            tar_addr.append(ret[0]['offset'])
        fret.append(tuple(tar_addr))
    return fret


def search_esil(r2, rg, strhead = 0, strtail = 0):
    print("searching for instructions...")
    range_str="e search.in=raw;e search.from={};e search.to={};".format(rg[0],rg[1])
    esil_search = "r4,+,0xffffffff,&,=[4]"
    esil_str = range_str+"/cej "+esil_search # str assignment to first local var. r4 not guaranteed
    
    ret = r2.cmd(esil_str).strip()
    if len(ret)<=2:
        print("no esil str found, esil: {}".format(esil_str))
        exit()
    res = json.loads(ret)
    regex_expr = "0x[0-9a-fA-F]{1,2}"

    ret = []
    for item in res:
        code = item['code']
        tmp = int(code.split(',')[1],16)
        #extract = code[:-len(esil_search)+1]
        #found = re.search(regex_expr, extract)
        #if found==None:
        #    print("esil invalid, extract: {}".format(extract))
        #    exit()
        #found = found.group(0)
        
        #ret.append(int(found,16))
        ret.append(tmp)

    ret.sort()
    ret = ret[strhead:]
    if strtail > 0 :
        ret = ret[:-strtail]
    return ret

def get_search_range_device_resume(r2, r2_id, funclist):
    FuncTar = funclist.FuncTar
    print("searching for xrefs in {}...".format(r2_id))
    ret = r2.cmd("afij {}".format(FuncTar)).strip()
    ret = json.loads(ret)
    start = ret[0]["offset"]
    end = ret[0]["offset"]+ret[0]["size"]
    return (start,end)

def get_search_range_device_initialize(r2, r2_id, funclist):
    FuncTar = funclist.FuncTar
    print("searching for xrefs in {}...".format(r2_id))
    ret = r2.cmd("afij {}".format(FuncTar)).strip()
    ret = json.loads(ret)
    start = ret[0]["offset"]
    end = ret[0]["offset"]+ret[0]["size"]
    return (start,end)

def set_flag_at(r2, bit, val=1):
    cur = r2.cmd("aer cpsr").strip()
    v = int(cur,16)
    mask = 2**bit
    if val == 1:
        v = v|mask
    else:
        v = v&~mask
    r2.cmd("aer cpsr=0x{:x}".format(v))
    
def esil_exec_all_branch(r2, rg ):
    r2.cmd("s {}".format(rg[0]))
    range_str="e search.in=raw;e search.from={};e search.to={};".format(rg[0],rg[1])
    Magic = "0x001DDDD"
    Garbage = "0x00100EE"
    ZF = 30
    
    print("scanning target analysis addresses...")
    branchs_json = r2.cmd(range_str+"/cej ,pc,=,}").strip()
    skips_json = r2.cmd(range_str+"/cej pc,lr,=").strip()
    target_str_json = r2.cmd(range_str+"/cj str").strip()
    target_ldr_json = r2.cmd(range_str+"/cj ldr").strip()
    branchs = []
    skips = []
    addrs = {}
    offsets_head = {}
    #branch_choices_list = {}
    reg_pattern = re.compile('(r\d{1,2})')
    for item in json.loads(branchs_json):
        branchs.append(item['offset'])
        #branch_choices_list[item['offset']] = [1,0]
    for item in json.loads(skips_json):
        skips.append(item['offset'])
    for item in json.loads(target_str_json):
        offset = item['offset']
        string = item['code']
        reses = re.findall(reg_pattern, string)
        offset_head_str = string.split(',')[-1].strip()
        if offset_head_str[-1]==']':
            offset_head_str = offset_head_str[0:-1]
        offset_head = int(offset_head_str,16)
        if len(reses)<2:
            print("Error: not enough regs in str instr at 0x{:x}".format(offset))
            exit()
        addrs[offset] = reses # str r0, [r1]: store r0 into place of r1
        offsets_head[offset] = offset_head
    for item in json.loads(target_ldr_json):
        offset = item['offset']
        string = item['code']
        reses = re.findall(reg_pattern, string)
        offset_head_str = string.split(',')[-1].strip()
        if offset_head_str[-1]==']':
            offset_head_str = offset_head_str[0:-1]
        offset_head = int(offset_head_str,16)
        if len(reses)<2:
            print("Error: not enough regs in ldr instr at 0x{:x}".format(offset))
            exit()
        addrs[offset] = reses # ldr r0, [r1]: load content of r1 into r0
        offsets_head[offset] = offset_head

    merged_list = {}
    for item in skips:
        merged_list[item] = 0
    for item in branchs:
        merged_list[item] = 1

    for item in addrs.keys():
        merged_list[item] = 2

    endpoint_json = r2.cmd(range_str+"/cej sp,+=").strip()
    endpoint = json.loads(endpoint_json)[0]['offset']
    merged_list[endpoint] = 3
    # debug print merged_list
    #for item in merged_list.keys():
    #    print("0x{:x}:{}, ".format(item, merged_list[item]), end='')
    #print("")
    targets_count = len([x for x in merged_list.keys() if merged_list[x]==2])
    print("Total target addresses found: {}".format(targets_count))

    print("generating block map...")
    
    # 0: function calls: skip
    # 1: branches: choose branch and step just one step
    # 2: exit: finish the run, check all unfinished things and rewind
    # 3: hit: record
    # execute step by step until found a better one. No breakpoint available.

    valid_list = []
    Magic_val = int(Magic,16)
        
    bb_list_json = json.loads(r2.cmd("afbj").strip())
    # generate map
    for item in bb_list_json:
        Basicblock(item,addrs)
    Basicblock.generate_map()
    print("generate map done")
    #Basicblock.print_map()

    def init_env(tar_reg):
        Basicblock.init()
        setup_str = "aei;aeim;s {};aeip;".format(rg[0])
        args_info = json.loads(r2.cmd("afvj").strip())

        r2.cmd(setup_str)
        for item in args_info['reg']:
            if item['ref'] == tar_reg:
                r2.cmd("aer {}={}".format(item['ref'],Magic))
            else:
                r2.cmd("aer {}={}".format(item['ref'],Garbage))
    def reset_env():
        reset_str = "aer0;aeim-;aei-;"
        r2.cmd(reset_str)
    
    valid_offset_list = []

    # iteratively call the function until the output is satisfying
    # normally only need to exhaust the outputs, but in case some results aren't needed, one can stop earlier
    def esil_executor(tar_ref):
        #print("start new round")
        init_env(tar_ref)
        #print("init done")
        dirty_bit = False
        r0_prev = r2.cmd("aer r0").strip()
        record = True
        cur_path = ""
        exhausted = False
        while True:
            tmp = int(r2.cmd("aer pc").strip(),16)
            if record:
                if len(cur_path)>0:
                    cur_path = cur_path+"->"
                cur_path = cur_path+"0x{:x}".format(tmp)
            record = False
            r0_val = r2.cmd("aer r0").strip()
            if r0_val != r0_prev:
                dirty_bit = False
            r0_prev = r0_val

            # then check if this is a visited location
            if tmp in merged_list.keys():
                inter = tmp
                if merged_list[inter] == 0:
                    #function, simply ignore them
                    r2.cmd("aess")
                    r2.cmd("aer r0={}".format(Garbage))
                    dirty_bit = True # r0 can hold return value sometimes, but not in void function.
                elif merged_list[inter] == 1:
                    # branch
                    cur_bb = Basicblock.get_block(tmp)
                    cur_choice = Basicblock.get_next_choice(cur_bb)
                    if cur_choice < 0:
                        if cur_choice == Basicblock.Loopend:
                            break
                        if cur_choice == Basicblock.Exhausted:
                            exhausted = True
                            break
                    else: # direct jump
                        set_flag_at(r2,ZF,cur_choice)
                    r2.cmd("aes")
                    record = True
                elif merged_list[inter] == 2:
                    # hit
                    cur_val0 = int(r2.cmd("aer {}".format(addrs[inter][0])).strip(),16) # if the target reg contains Magic
                    cur_val1 = int(r2.cmd("aer {}".format(addrs[inter][1])).strip(),16) # if the target reg contains Magic
                    if cur_val0==Magic_val or cur_val1==Magic_val:
                        print("hit 0x{:x}: {}={}. {}={}".format(inter,(addrs[inter][0]),hex(cur_val0),(addrs[inter][1]),hex(cur_val1)))
                        valid_list.append(inter)
                        off = offsets_head[inter]
                        if off not in valid_offset_list:
                            valid_offset_list.append(off)
                    merged_list[inter] = 9 # mark as visited
                    r2.cmd("aes")
                elif merged_list[inter] == 3:
                    # exit
                    break
                else: # 9
                    r2.cmd("aes")
            else:
                r2.cmd("aes")
        reset_env()
        #print("execution end")
        ret_flag = True
        #unfinished = [x for x in merged_list.keys() if merged_list[x]==2]
        #print("Unfinished:")
        #print(unfinished)
        #print("Finished:")
        #print(valid_list)

        cur_path = "Path:"+cur_path
        if not exhausted:
            if 2 in merged_list.values(): # still have value remaining
                ret_flag = False
        return (ret_flag,valid_offset_list,cur_path)
        
    return esil_executor
    

#=================================================================

def process_i2c_new_device(r2,r2_id, struct):
    print ("processing i2c_new_device...")
    ls = ['platform_data','bus','type','of_node','parent']
    FuncTar = "sym.i2c_new_device"
    FuncTarSubs = [
                [
                    "sym.i2c_check_addr_busy",
                    "sym.dev_set_name"
                ],
                [
                    "sym.kmem_cache_alloc",
                    "sym.strlcpy"
                ]
            ]
    funclist = FuncList(FuncTar,FuncTarSubs)
    anal_tar_func(r2,r2_id,funclist)
    rg = get_search_range_i2c_0(r2,r2_id,funclist)
    ret = []
    ret=ret+ search_esil(r2,rg[0]) 
    print(ret)
    ret=ret+ search_esil(r2,rg[1],strtail=1,strhead=1) 
    print(ret)
    ret.sort()
    ret = [x-0x20 for x in ret] # due to i2c_client offset
    prt_ret = [hex(x) for x in ret]
    print("Found matches: {}".format(prt_ret))
    return struct.map_list(ret, ls)


def process_device_resume(r2, r2_id, struct):
    print ("processing device_resume...")
    ls = ['power.is_prepared','pm_domain','type','class','bus','driver','mutex']
    FuncTar = "sym.device_resume"
    FuncTarSubs = []
    funclist = FuncList(FuncTar,FuncTarSubs)
    anal_tar_func(r2,r2_id,funclist)
    rg = get_search_range_device_resume(r2,r2_id,funclist)
    iters = esil_exec_all_branch(r2,rg)
    ret = iters("r0")
    while ret[0]==False:
        ret = iters("r0")
    ret = ret[1]
    ret.sort()
    prt_ret = [hex(x) for x in ret]
    print("Found matches: {}".format(prt_ret))
    return struct.map_list(ret,ls)

def process_device_initialize(r2, r2_id, struct):
    print("processing device_initialize...")
    ls = []
    FuncTar = "sym.device_initialize"
    FuncTarSubs = []
    funclist = FuncList(FuncTar,FuncTarSubs)
    anal_tar_func(r2,r2_id,funclist)
    rg = get_search_range_device_initialize(r2,r2_id,funclist)
    ret = []
    return struct.map_list(ret,ls)

def process():
    msm_res = process_i2c_new_device(Msm_r2, "msm", Struct_msm)
    van_res = process_i2c_new_device(Van_r2, "vanilla",Struct_vanilla)
    print("=================================================")
    if msm_res == False or van_res == False:
        print("Offset processing failed. Exiting...")
        exit()
    msm_res = process_device_resume(Msm_r2, "msm", Struct_msm)
    van_res = process_device_resume(Van_r2, "vanilla",Struct_vanilla)
    print("=================================================")
    if msm_res == False or van_res == False:
        print("Offset processing failed. Exiting...")
        exit()

    # the actual comparing
    Struct_msm.cmp(Struct_vanilla)

    print("=================================================")
    print("analysis done!")

def init():
    global Msm_r2
    global Van_r2
    if(len(sys.argv)<3):
        print("Usage: main.py van_bin msm_bin")
        exit()
    print("reading target files...")

    Msm_r2 = r2pipe.open(sys.argv[2],["-q"])
    Van_r2 = r2pipe.open(sys.argv[1],["-q"])
    if(Msm_r2==None):
        print("Error: msm kernel read failed.")
        exit()
    if(Van_r2==None):
        print("Error: vanilla kernel read failed.")
        exit()
    print("=================================================")
    print("reading files successful.")
    print("processing...")

if __name__ == "__main__":
    init()
    process()
