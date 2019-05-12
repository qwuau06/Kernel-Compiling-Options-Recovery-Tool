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

class FuncRange:
    def __init__(self,FuncTar,subflags):
        self.FuncTar = FuncTar
        self.SubFlags = subflags 

def anal_tar_func(r2, r2_id, funclist):
    FuncTar = funclist.FuncTar
    FuncTarSubs = funclist.SubFlags
    print("analyzing target function in {}...".format(r2_id))
    ret = r2.cmd("fs symbols;f~"+FuncTar).strip()
    if len(ret)<=2:
        print(r2_id+" doesn't have function "+FuncTar)
        exit();
    r2.cmd("af @ {}".format(FuncTar))
    if FuncTarSubs == None:
        return
    for rgs in FuncTarSubs:
        for item in rgs:
            ret = r2.cmd("fs symbols;f~"+item).strip()
            if len(ret)<=2:
                print(r2_id+" doesn't have function "+item)
                exit();
            r2.cmd("af @ {}".format(item))

def strip_head_tail(ret, head, tail):
    ret = ret[head:]
    if tail>0:
        ret = ret[:tail]
    return ret

#=================================================================

Range_str = "e search.in=raw; e search.from={}; e search.to={};"

def r2search(r2, rg, search_cmd, proc=lambda ret: [i for j in ret for i in j]):
    if isinstance(rg[0],int):
        rg = [rg]
    ret = []
    for item in rg:
        rg_str = Range_str.format(item[0],item[1])
        res = r2.cmd(rg_str+search_cmd).strip()
        ret.append(res)
    if len(ret)>0:
        return proc(ret)
    return None

def search_esil(r2, rg, esil_search, proc = lambda x:x):
    print("searching for instructions...")
    esil_str = "/cej "+esil_search
    
    ret = r2search(r2, rg, esil_str, proc=lambda x:x)
    if len(ret[0])<=2:
        print("no esil str found, esil: {}".format(esil_str))
        exit()
    res = json.loads(ret[0])

    ret = [proc(x) for x in res]
    return ret

def get_search_range(r2, r2_id, funclist):
    FuncTar = funclist.FuncTar
    print("searching for xrefs in {}...".format(r2_id))
    ret = []
    ret = r2.cmd("afij {}".format(FuncTar)).strip()
    ret = json.loads(ret)
    start = ret[0]["offset"]
    end = ret[0]["offset"]+ret[0]["size"]
    return start,end

def get_search_range_i2c_0(r2, r2_id,funclist):
    start,end = get_search_range(r2,r2_id,funclist)
    FuncTarSubs = funclist.SubFlags
    range_str= Range_str.format(start,end)
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
    return (start,end), fret

def get_search_range_device_resume(r2, r2_id, funclist):
    return get_search_range(r2,r2_id,funclist)

def get_search_range_device_initialize(r2, r2_id, funclist):
    start,end = get_search_range(r2,r2_id,funclist)
    
    ret = r2.cmd("afbj @ {}".format(funclist.FuncTar))
    ret = json.loads(ret)
    fret = []
    for item in ret:
        sub_start = item["addr"]
        sub_size = item["size"]
        fret.append(tuple((sub_start, sub_start+sub_size)))
    if not fret[0][0] == start:
        fret[0],fret[1] = fret[1], fret[0]

    return (start,end),fret

def set_flag_at(r2, bit, val=1):
    cur = r2.cmd("aer cpsr").strip()
    v = int(cur,16)
    mask = 2**bit
    if val == 1:
        v = v|mask
    else:
        v = v&~mask
    r2.cmd("aer cpsr=0x{:x}".format(v))
    

def esil_exec_all_branch(r2, rg, starting_addr ):
    r2.cmd("s {}".format(starting_addr))
    #range_str=Range_str.format(rg[0],rg[1])
    Magic = "0x001DDDD"
    Garbage = "0x00100EE"
    ZF = 30
    
    lmbd = lambda ret: json.dumps([t for x in ret for t in json.loads(x or "[]")])
    print("scanning target analysis addresses...")
    branchs_json = r2search(r2, rg, "/cej ,pc,=,}",proc=lmbd) or "[]"
    skips_json = r2search(r2, rg, "/cej pc,lr,=",proc=lmbd) or "[]"
    target_str_json = r2search(r2, rg, "/cj str",proc=lmbd) or "[]"
    target_ldr_json = r2search(r2, rg, "/cj ldr",proc=lmbd) or "[]"
    
    #branchs_json = r2.cmd(range_str+"/cej ,pc,=,}").strip()
    #skips_json = r2.cmd(range_str+"/cej pc,lr,=").strip()
    #target_str_json = r2.cmd(range_str+"/cj str").strip()
    #target_ldr_json = r2.cmd(range_str+"/cj ldr").strip()
    addrs = {}
    offsets_head = {}
    reg_pattern = re.compile('(r\d{1,2})')

    branchs = [item['offset'] for item in json.loads(branchs_json)]
    skips = [item['offset'] for item in json.loads(skips_json)]
    for item in json.loads(target_str_json):
        offset = item['offset']
        string = item['code']
        reses = re.findall(reg_pattern, string)
        offset_head_str = string.split(',')[-1].strip()
        # TODO: properly deal with write back
        if offset_head_str[-1]=='!':
            offset_head_str = offset_head_str[0:-1]
        if offset_head_str[-1]==']':
            offset_head_str = offset_head_str[0:-1]
        offset_head = int(offset_head_str,16)
        if len(reses)<2:
            print("Error: not enough regs in str instr at 0x{:x}".format(offset))
            reses.append("pc")
            #exit()
        addrs[offset] = reses # str r0, [r1]: store r0 into place of r1
        offsets_head[offset] = offset_head
    for item in json.loads(target_ldr_json):
        offset = item['offset']
        string = item['code']
        reses = re.findall(reg_pattern, string)
        offset_head_str = string.split(',')[-1].strip()
        # TODO: properly deal with write back
        if offset_head_str[-1]=='!':
            offset_head_str = offset_head_str[0:-1]
        if offset_head_str[-1]==']':
            offset_head_str = offset_head_str[0:-1]
        offset_head = int(offset_head_str,16)
        if len(reses)<2:
            print("Error: not enough regs in ldr instr at 0x{:x}".format(offset))
            reses.append("pc")
            #exit()
        addrs[offset] = reses # ldr r0, [r1]: load content of r1 into r0
        offsets_head[offset] = offset_head

    merged_list = {}
    for item in skips:
        merged_list[item] = 0
    for item in branchs:
        merged_list[item] = 1

    for item in addrs.keys():
        merged_list[item] = 2

    endpoint_json = r2search(r2, rg, "/cej sp,+=", proc=lambda x:x[0])
    #endpoint_json = r2.cmd(range_str+"/cej sp,+=").strip()
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
    tarfunc = "sym.i2c_new_device"
    tarfuncsubs = [
                [
                    "sym.i2c_check_addr_busy",
                    "sym.dev_set_name"
                ],
                [
                    "sym.kmem_cache_alloc",
                    "sym.strlcpy"
                ]
            ]
    funclist = FuncRange(tarfunc,tarfuncsubs)
    anal_tar_func(r2,r2_id,funclist)
    _,rg = get_search_range_i2c_0(r2,r2_id,funclist)

    esil_search = "r4,+,0xffffffff,&,=[4]"
    reg_proc = lambda item: int(item['code'].split(',')[1],16)
    ret = []
    ret=ret+ search_esil(r2,rg[0],esil_search, proc=reg_proc) 
    ret.sort()
    print(ret)
    ret_tmp= search_esil(r2,rg[1],esil_search, proc=reg_proc) 
    ret_tmp.sort()
    ret_tmp = strip_head_tail(ret_tmp,1,1)
    ret = ret+ret_tmp
    print(ret)
    branch_search = ",pc,=,}"
    br_count = search_esil(r2,rg[1],branch_search)
    if len(ret)==6 or len(br_count)>=2:
        ls.append('archdata')
    ret.sort()
    ret = [x-0x20 for x in ret] # due to i2c_client offset
    prt_ret = [hex(x) for x in ret]
    print("Found matches: {}, mapping to {}".format(prt_ret,ls))
    return struct.map_list(ret, ls)


def process_device_resume(r2, r2_id, struct):
    print ("processing device_resume...")
    ls = ['power.is_prepared','pm_domain','type','class','bus','driver','mutex']
    tarfunc = "sym.device_resume"
    funclist = FuncRange(tarfunc,None)
    anal_tar_func(r2,r2_id,funclist)
    rg = get_search_range_device_resume(r2,r2_id,funclist)
    
    iters = esil_exec_all_branch(r2,rg,rg[0])
    ret = iters("r0")
    while ret[0]==False:
        ret = iters("r0")
    ret = ret[1]
    ret.sort()
    prt_ret = [hex(x) for x in ret]
    print("Found matches: {}, mapping to {}".format(prt_ret,ls))
    return struct.map_list(ret,ls)


# detect __raw_spin_lock_init => CONFIG_DEBUG_SPINLOCK
# detect leaf function => CONFIG_PM_SLEEP not set!!!!

def process_device_initialize(r2, r2_id, struct):
    print("processing device_initialize...")
    ls = ["devres_head", "dma_pools","kobj"]
    tarfunc = "sym.device_initialize"
    funclist = FuncRange(tarfunc,None)
    anal_tar_func(r2,r2_id,funclist)
    rg, rgs = get_search_range_device_initialize(r2,r2_id,funclist)

    # hard coded part option recover. needs refactoring later
    refs = [hex(x["to"]) for x in json.loads(r2.cmd("s "+tarfunc+"; afxj").strip()) if x["type"]=="call"] # get all func calls
    ref_funcs = [r2.cmd("?w "+ref).strip().split(' ')[1].strip() for ref in refs]

#    struct = Struct_vanilla
#    if r2_id=="msm":
#        struct = Struct_msm

#    if "sym.complete_all" in ref_funcs:
#        struct.oplist.set_option("CONFIG_PM_SLEEP")
#    else:
#        struct.oplist.set_option("CONFIG_PM_SLEEP",False)

#    res = r2.cmd("fs symbols;f~sym.pm_runtime_init").strip()
#    if len(res)<2:
#        struct.oplist.set_option("CONFIG_PM_RUNTIME",False)
#    else:
#        struct.oplist.set_option("CONFIG_PM_RUNTIME")

    # hard code part end. only deal with first part of the code no matter what.

    ret = []
    iters = esil_exec_all_branch(r2,rgs,rg[0])
    ret = iters("r0")
    print(ret)
    ret = ret[1]
    ret.sort()

    # remove devres_lock: it's position is fixed anyway
    devres_lock = None
    for item in ret:
        if item+4 in ret and item-4 in ret:
            devres_lock = item-4
            break
    if devres_lock != None:
        ret.remove(devres_lock)

    ret = [x for x in ret if x-4 not in ret]

    prt_ret = [hex(x) for x in ret]
    print("Found matches: {}, mapping to {}".format(prt_ret,ls))
    return struct.map_list(ret,ls)


def process():
    def run_comp(func):
        msm_res = func(Msm_r2, "msm", Struct_msm)
        van_res = func(Van_r2, "vanilla",Struct_vanilla)
        print("=================================================")
        if msm_res == False or van_res == False:
            print("Offset processing failed. Exiting...")
            exit()
    run_comp(process_i2c_new_device)
    run_comp(process_device_resume)
    run_comp(process_device_initialize)

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
