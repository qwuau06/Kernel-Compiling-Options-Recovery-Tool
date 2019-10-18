import json
import r2pipe
import re

from Basicblock import Basicblock

class FuncArgs:
    def __init__(self, funcName, arglist, ret=True):
        self.name = funcName
        self.args = arglist
        self.ret = ret

class FuncRange:
    def __init__(self,FuncTar,subflags):
        self.FuncTar = FuncTar
        self.SubFlags = subflags 

def r2dbgprt(r2,s):
    print("debug print: {}".format(s))
    print(r2.cmd(s).strip())

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


def direct_check_op(r2, struct, funcname, opname, *, force=False):
    ret = r2.cmd("fs symbols;f~{}".format(funcname)).strip()
    if len(ret)>5:
        struct.oplist.set_option(opname)
        return True
    else:
        if force:
            struct.oplist.set_option(opname,False)
        return False

class Sim_ESIL(object):
    def __init__(self, instr,name):
        self.instr = instr
        self.name = name

    def __enter__(self):
        frags = self.instr.strip().split(' ')
        if self.name not in frags[0]:
            print(self.instr)
            print("Error: not {} command".format(self.name))
            import traceback
            traceback.print_stack()
            exit()
        cond = frags[0][len(self.name):].strip()
        frags = frags[1:]
        has_off = False
        if "[" not in frags[-1]:
            has_off = True
        frags[:] = [x.strip(',').strip('[').strip(']')  for x in frags]
        return tuple((frags, has_off, cond))

    def __exit__(self):
        None


def sim_esil_strex(r2, instr):
    with Sim_ESIL(instr, "strex") as properties:
        frags = properties[0]
        has_off = properties[1]
        cond = properties[2]
        esil_cmd = None
        if not has_off:
            esil_cmd = "{},{},0xffffffff,&,=[4]".format(frags[1], frags[2])
        else:
            esil_cmd = "{},{},{},+,0xffffffff,&,=[4]".format(frags[1], frags[3], frags[2])
        if len(cond)>0:
            if cond == "eq":
                esil_cmd = "zf,?{{,{},}}".format(esil_cmd)
            elif cond == "ne":
                esil_cmd = "zf,!,?{{,{},}}".format(esil_cmd)
        esil_cmd = "ae "+esil_cmd
        r2.cmd(esil_cmd)
        r2.cmd("aer {}=0".format(frags[0]))

def sim_esil_ldrex(r2, instr):
    # ldr r2, [r3, 4]
    with Sim_ESIL(instr, "ldrex") as properties:
        frags = properties[0]
        has_off = properties[1]
        cond = properties[2]
        esil_cmd = None
        if not has_off:
            esil_cmd = "{},0xffffffff,&,[4],0xffffffff,&,{},=".format(frags[1],frags[0])
        else:
            esil_cmd = "{},{},+,0xffffffff,&,[4],0xffffffff,&,{},=".format(frags[2],frags[1],frags[0])
        if len(cond)>0:
            if cond == "eq":
                esil_cmd = "zf,?{{,{},}}".format(esil_cmd)
            elif cond == "ne":
                esil_cmd = "zf,!,?{{,{},}}".format(esil_cmd)
        esil_cmd = "ae "+esil_cmd
        r2.cmd(esil_cmd)

def sim_esil_strd(r2, instr):
    with Sim_ESIL(instr, "strd") as properties:
        frags = properties[0]
        has_off = properties[1]
        cond = properties[2]
        esil_cmd = None
        #esil_cmd0 = None
        #esil_cmd1 = None
        if not has_off:
            esil_cmd = "ae {},{},0xffffffff,&,=[4],{},4,{},+,0xffffffff,&,=[4]".format(frags[0],frags[2],frags[1],frags[2])
            #esil_cmd0 = "{},{},0xffffffff,&,=[4]".format(frags[0],frags[2])
            #esil_cmd1 = "{},4,{},+,0xffffffff,&,=[4]".format(frags[1],frags[2])
        else:
            esil_cmd = "ae {},{},{},+,0xffffffff,&,=[4],{},4,{},+,{},+,0xffffffff,&,=[4]".format(frags[0],frags[3],frags[2],frags[1],frags[3],frags[2])
            #off = int(frags[3],16)
            #esil_cmd0 = "{},{},{},+,0xffffffff,&,=[4]".format(frags[0],off,frags[2])
            #esil_cmd1 = "{},{},{},+,0xffffffff,&,=[4]".format(frags[1],off+4,frags[2])
        r2dbgprt(r2,"aer {}".format(frags[2]))
        r2dbgprt(r2,"aer {}".format(frags[0]))
        #r2.cmd("ae {}".format(esil_cmd0))
        print(esil_cmd)
        r2dbgprt(r2,"aer {}".format(frags[2]))
        r2dbgprt(r2,"aer {}".format(frags[0]))
        r2.cmd(esil_cmd)

def sim_esil_ldrd(r2, instr):
    with Sim_ESIL(instr, "ldrd") as properties:
        frags = properties[0]
        has_off = properties[1]
        cond = properties[2]
        esil_cmd = None
        if not has_off:
            esil_cmd = "ae {},0xffffffff,&,[4],0xffffffff,&,{},=,{},4,+,0xffffffff,&,[4],0xffffffff,&,{},=".format(frags[2],frags[0],frags[2],frags[1])
        else:
            esil_cmd = "ae {},{},+,0xffffffff,&,[4],0xffffffff,&,{},=,{},{},+,4,+,0xffffffff,&,[4],0xffffffff,&,{},=".format(frags[2],frags[3],frags[0],frags[2],frags[3],frags[1])
        r2.cmd(esil_cmd)

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
    if len(ret)<=2:
        return -1,-1
    ret = json.loads(ret)
    start = ret[0]["offset"]
    end = ret[0]["offset"]+ret[0]["size"]
    return start,end


def set_flag_at(r2, bit, val=1):
    cur = r2.cmd("aer cpsr").strip()
    v = int(cur,16)
    mask = 2**bit
    if val == 1:
        v = v|mask
    else:
        v = v&~mask
    r2.cmd("aer cpsr=0x{:x}".format(v))
    
#=================================================================
def esil_exec_all_branch(r2, rg, starting_addr, func_arg_list=[]):
    r2.cmd("s {}".format(starting_addr))
    #range_str=Range_str.format(rg[0],rg[1])
    Magic = "0x0010DDDD"
    Garbage = "0x00100EEE"
    ZF = 30
    
    lmbd = lambda ret: json.dumps([t for x in ret for t in json.loads(x or "[]")])
    print("scanning target analysis addresses...")
    branchs_json = r2search(r2, rg, "/cej ,pc,=,}",proc=lmbd) or "[]"
    skips_json = r2search(r2, rg, "/cej pc,lr,=",proc=lmbd) or "[]"
    target_str_json = r2search(r2, rg, "/cj str",proc=lmbd) or "[]"
    target_ldr_json = r2search(r2, rg, "/cj ldr",proc=lmbd) or "[]"
    target_add_json = r2search(r2, rg, "/cj add",proc=lmbd) or "[]"

    # due to incomplete ESIL code, these needs to be manually implemented.
    # strd and ldrd as two-step ESILs; strex as normal str + mov
    list_strex = json.loads(r2search(r2, rg, "/cj strex",proc=lmbd) or "[]")
    list_ldrex = json.loads(r2search(r2, rg, "/cj ldrex",proc=lmbd) or "[]")
    list_strd = json.loads(r2search(r2, rg, "/cj strd",proc=lmbd) or "[]")
    list_ldrd = json.loads(r2search(r2, rg, "/cj ldrd",proc=lmbd) or "[]")

    #branchs_json = r2.cmd(range_str+"/cej ,pc,=,}").strip()
    #skips_json = r2.cmd(range_str+"/cej pc,lr,=").strip()
    #target_str_json = r2.cmd(range_str+"/cj str").strip()
    #target_ldr_json = r2.cmd(range_str+"/cj ldr").strip()
    addrs = {}
    offsets_head = {}
    reg_pattern = re.compile('(r\d{1,2}|sb)')
    off_pattern = re.compile('\[(.*)\]')
    other_pattern = re.compile('\w+ (.*)\[')

    branchs = [item['offset'] for item in json.loads(branchs_json)]
    skips = [item['offset'] for item in json.loads(skips_json)]

    def proc_json(item, addrs, offsets_head, *, proc_regs=lambda x,y:[x,y[0]], ):
        offset = item['offset']
        string = item['code']
        tar = re.findall(off_pattern, string)[0].strip().split(', ')
        reg_offset = 0
        rn = None
        if len(tar)==2:
            reg_offset = int(tar[1].strip(),16)
        if len(tar)>0:
            rn = tar[0].strip()
        list_rts = re.findall(other_pattern, string)[0].split(', ')
        list_rts = [x for x in list_rts if x!=""]
        for x in list_rts:
            if re.match(reg_pattern,x) == None:
                print(list_rts)
                print("Detected non-reg in instr at 0x{:x}".format(offset))
                import traceback
                traceback.print_stack()
                exit()
        regs = proc_regs(rn,list_rts)
        offsets_head[offset] = reg_offset
        addrs[offset] = regs # str r0, [r1]: store r0 into place of r1

    for item in json.loads(target_str_json):
        if item in list_strex or item in list_strd:
            continue
        proc_json(item, addrs, offsets_head)
    for item in json.loads(target_ldr_json):
        if item in list_ldrex or item in list_ldrd:
            continue
        proc_json(item, addrs, offsets_head, proc_regs=lambda x,y:[x,"blank"])
    for item in json.loads(target_add_json):
        offset = item['offset']
        string = item['code']
        reses = re.findall(reg_pattern, string)
        offset_head_str = string.split(',')[-1].strip()
        # TODO: properly deal with write back
        offset_head = int(offset_head_str,16)
        if len(reses)<2:
            print("not enough regs in add instr at 0x{:x}. Skipping...".format(offset))
            reses.append("pc")
            #exit()
        addrs[offset] = reses # ldr r0, [r1]: load content of r1 into r0
        offsets_head[offset] = offset_head

    special_list = {}
    special_instr = {}
    # TODO: temporary solutions here. updates may clear it up.
#    for item in list_strex:
#        proc_json(item, addrs, offsets_head, proc_regs=lambda x,y: [x, y[1]])
#        special_list[item['offset']] = 0
#        special_instr[item['offset']] = item['code']
#    for item in list_ldrex:
#        proc_json(item, addrs, offsets_head)
#        special_list[item['offset']] = 1
#        special_instr[item['offset']] = item['code']
    for item in list_strd:
        proc_json(item, addrs, offsets_head)
#        special_list[item['offset']] = 2
#        special_instr[item['offset']] = item['code']
    for item in list_ldrd:
        proc_json(item, addrs, offsets_head)
        special_list[item['offset']] = 3
        special_instr[item['offset']] = item['code']

    special_act = [sim_esil_strex, sim_esil_ldrex, sim_esil_strd, sim_esil_ldrd]

    merged_list = {}
    for item in skips:
        merged_list[item] = 0
    for item in branchs:
        merged_list[item] = 1

    for item in addrs.keys():
        merged_list[item] = 2


    # debug print merged_list
    for item in merged_list.keys():
        print("0x{:x}:{}, ".format(item, merged_list[item]), end='')
    print("")
    targets_count = len([x for x in merged_list.keys() if merged_list[x]==2])
    print("Total target addresses found: {}".format(targets_count))
    print([hex(x) for x in merged_list.keys() if merged_list[x]==2])

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
        #Basicblock(item,addrs)
        Basicblock(item)
    Basicblock.generate_map()
    print("generate map done")
    #Basicblock.print_map()

    #endpoint_json = r2search(r2, rg, "/cej sp,+=", proc=lambda x:x[0])
    #endpoint = json.loads(endpoint_json)[0]['offset']
    endpoints = Basicblock.get_all_ends()
    for item in endpoints:
        merged_list[item] = 3

    active_reg_list = []

    def init_env(tar_reg):
        Basicblock.init()
        setup_str = "aer0;aei;aeim 0x100000 0xf0000 free_space;s {};aeip;".format(rg[0])
        args_info = json.loads(r2.cmd("afvj").strip())

        active_reg_list.append(tar_reg)

        r2.cmd(setup_str)
        for item in args_info['reg']:
            r2.cmd("aer {}={}".format(item['ref'],Garbage))
        r2.cmd("aer {}={}".format(tar_reg,Magic))

    def reset_env():
        reset_str = "aeim-;aei-;"
        r2.cmd(reset_str)
    
    valid_offset_list = []

    # iteratively call the function until the output is satisfying
    # normally only need to exhaust the outputs, but in case some results aren't needed, one can stop earlier
    def esil_executor(tar_ref):
        #print("start new round")
        init_env(tar_ref)
        #print("init done")
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

            # then check if this is a visited location
            if tmp in merged_list.keys():
                inter = tmp
                if merged_list[inter] == 0:
                    #function, extract arguments
                    if len(func_arg_list)==0:
                        r2.cmd("aess;aer r0={}".format(Garbage))
                    else:
                        func_name_raw = r2.cmd("axf @ {}".format(r2.cmd("aer pc"))).strip()
                        #print("function at {}.".format(r2.cmd("aer pc").strip()))
                        if len(func_name_raw)<=2:
                            r2.cmd("aess;aer r0={}".format(Garbage))
                        else:
                            func_name_raw = func_name_raw.split(' ')[2]
                            func_arg_tar = None
                            for func_arg in func_arg_list:
                                if func_arg.name == func_name_raw:
                                    func_arg_tar = func_arg
                                    break
                            if func_arg_tar != None:
                                for reg_name in func_arg_tar.args:
                                    off_chr = r2.cmd("aer {}".format(reg_name)).strip()
                                    off = int(off_chr,16)-Magic_val
                                    if off not in valid_offset_list:
                                        print("arg hit 0x{:x} of function {} at {}; orig {}".format(off, func_arg_tar.name, r2.cmd("aer pc").strip(),off_chr))
                                        valid_offset_list.append(off)
                            r2.cmd("aess")
                            # by default we assume every function has a return value which is not of interest
                            if func_arg_tar == None or func_arg_tar.ret:
                                r2.cmd("aer r0={}".format(Garbage))
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
#                    list_regval = []
#                    for reg in addrs[inter]:
#                        reg_val = int(r2.cmd("aer {}".format(reg)).strip(),16)
#                        list_regval.append(reg_val)
#                    off_from = None
#                    for other_off in [0]+valid_offset_list:
#                        known_mem = Magic_val + other_off
#                        if known_mem in list_regval:
#                            off_from = other_off
#                            break
#                    if off_from != None:
#                        prt = "hit 0x{:x}: ".format(inter)
#                        for idx in range(len(list_regval)):
#                            prt += "{}={}. ".format(addrs[inter][idx], list_regval[idx])
#                        print(prt)
#                        valid_list.append(inter)
#                        off = offsets_head[inter]+off_from
                    cur_val0 = int(r2.cmd("aer {}".format(addrs[inter][0])).strip(),16) # if the target reg contains Magic
                    cur_val1 = int(r2.cmd("aer {}".format(addrs[inter][1])).strip(),16) # if the target reg contains Magic
                    off_from = None
                    for other_off in [0]+valid_offset_list:
                        known_mem = Magic_val + other_off
                        if cur_val0==known_mem or cur_val1==known_mem:
                            off_from = other_off
                            break
                    if off_from != None:
                        valid_list.append(inter)
                        off = offsets_head[inter]+off_from
                        print("hit 0x{:x}: {}={}. {}={}, off=0x{:x}".format(inter,(addrs[inter][0]),hex(cur_val0),(addrs[inter][1]),hex(cur_val1),offsets_head[inter]))
                        if off not in valid_offset_list:
                            valid_offset_list.append(off)
                    merged_list[inter] = 9 # mark as visited
#                    cur_instr = r2.cmd("ao 1").split('\n')[1].split(':')[1].strip()
#                    cur_opcode = cur_instr.split(' ')[0]
                    if inter not in special_list.keys():
                        r2.cmd("aes")
                    else:
                        r2.cmd("aess")
                        special_act[special_list[inter]](r2,special_instr[inter])
#                    if "ldr" in cur_instr:
#                        r2.cmd("aer {}={}".format(addrs[inter][1],Garbage))
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
