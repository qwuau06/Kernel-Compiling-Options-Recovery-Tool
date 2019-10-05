import r2pipe

from utils import *
from Structs import StructBase, OptionList, spinlock_t, listhead_t

class StructDevice(StructBase):
    Members = [
            "parent",           # 4
            "p",                # 4
            "kobj",             # 36
            "init_name",        # 4
            "type",             # 4 
            "mutex",            # EXPAND
            "bus",              # 4
            "driver",           # 4
            "platform_data",    # 4
            "power",            # EXPAND
            "pm_domain",        # 4
            "pins",             # CONFIG_PINCTRL: 4
            "numa_node",        # CONFIG_NUMA: 4 # not applicable
            "dma_mask",         # 4
            "coherent_dma_mask",# 8
            "dma_parms",        # 4
            "dma_pools",        # 8
            "dma_mem",          # 4
            "cma_area",         # CONFIG_CMA: 4
            "archdata",         # CONFIG_DMABOUNCE: +4; CONFIG_IOMMU_API: +4
            "of_node",          # 4
            "devt",             # 4
            "id",               # 4
            "devres_lock",      # spinlock_t
            "devres_head",      # 8
            "knode_class",      # 16 min
            "class",            # 4
            "groups",           # 4
            "dev",              # 4
            "__end__"           # placeholder
            ]
    SubMembers = {}
    SubMembers["mutex"] = [
            "count",            # 4
            "wait_lock",        # spinlock_t
            "wait_list",        # 8
            "owner",            # CONFIG_DEBUG_MUTEXES || CONFIG_SMP : 4
            "name",             # CONFIG_DEBUG_MUTEXES: 4
            "magic",            # CONFIG_DEBUG_MUTEXES: 4
            "dep_map",          # CONFIG_DEBUG_LOCK_ALLOC: lockdep_map
            "__end_mutex__"
            ]
    SubMembers["power"] = [
            "power_state",      # 4
            "can_wakeup",       # -
            "async_suspend",    # 4
            "is_prepared",      # -
            "is_suspended",     # -
            "ignore_children",  # 1
            "lock",             # spinlock_t
            "entry",            # CONFIG_PM_SLEEP: 8
            "completion",       # CONFIG_PM_SLEEP: EXPAND
            "wakeup",           # CONFIG_PM_SLEEP: 4
            "wakeup_path",      # CONFIG_PM_SLEEP: 1
            "should_wakeup",    # ! CONFIG_PM_SLEEP: 4
            "suspend_timer",    # CONFIG_PM_RUNTIME: 28; CONFIG_TIMER_STATS: +24 min; CONFIG_LOCKDEP: +lockdep_map
            "timer_expires",    # CONFIG_PM_RUNTIME: 4
            "work",             # CONFIG_PM_RUNTIME: 16; CONFIG_LOCKDEP: +lockdep_map
            "wait_queue",       # CONFIG_PM_RUNTIME: 8+spinlock_t
            "usage_count",      # CONFIG_PM_RUNTIME: 4
            "child_count",      # CONFIG_PM_RUNTIME: 4
            "disable_depth",            # CONFIG_PM_RUNTIME: -
            "idle_notification",        # CONFIG_PM_RUNTIME: -
            "request_pending",          # CONFIG_PM_RUNTIME: -
            "deferred_resume",          # CONFIG_PM_RUNTIME: -
            "run_wake",                 # CONFIG_PM_RUNTIME: -
            "runtime_auto",             # CONFIG_PM_RUNTIME: -
            "no_callbacks",             # CONFIG_PM_RUNTIME: -
            "irq_safe",                 # CONFIG_PM_RUNTIME: -
            "use_autosuspend",          # CONFIG_PM_RUNTIME: -
            "timer_autosuspends",       # CONFIG_PM_RUNTIME: 4
            "request",                  # CONFIG_PM_RUNTIME: 4
            "runtime_status",           # CONFIG_PM_RUNTIME: 4
            "runtime_error",            # CONFIG_PM_RUNTIME: 4
            "autosuspend_delay",        # CONFIG_PM_RUNTIME: 4
            "last_busy",                # CONFIG_PM_RUNTIME: 4
            "active_jiffies",           # CONFIG_PM_RUNTIME: 4
            "suspend_jiffies",          # CONFIG_PM_RUNTIME: 4
            "accounting_timestamp",     # CONFIG_PM_RUNTIME: 4
            "suspend_time",             # CONFIG_PM_RUNTIME: 8
            "max_time_suspended_ns",    # CONFIG_PM_RUNTIME: 8
            "pq_req",           # CONFIG_PM_RUNTIME: 4
            "subsys_data",      # 4
            "constraints"       # 4
            ]
    SubMembers["kobj"] = [
            "name",             # 4
            "entry",            # 8
            "parent",           # 4
            "kset",             # 4
            "ktype",            # 4
            "sd",               # 4
            "kref",             # 4
            "state_initialized",# -
            "state_in_sysfs",   # -
            "state_add_uevent_sent",    # -
            "state_remove_uevent_sent", # -
            "uevent_suppress"   # 4
            ]
    SubMembers["power.completion"] = [
            "done",             # 4
            "wait"              # EXPAND
            ]
    SubMembers["power.completion.wait"] = [
            "lock",             # spinlock_t
            "task_list"         # 8
            ]
    SubMembers["knode_class"] = [
            "n_klist",          # 4
            "n_node",           # 8
            "n_ref"             # 4
            ]
    SubMembers["archdata"] = [
            "dma_ops",          # 4, *msm kernel only
            "dmabounce",        # CONFIG_DMABOUNCE: 4
            "iommu",            # CONFIG_IOMMU_API: 4
            "mapping",          # CONFIG_ARM_DMA_USE_IOMMU: 4, *msm kernel only
            ]
    SubMembers["devres_lock"] = spinlock_t.copy()
    SubMembers["mutex.wait_lock"] = spinlock_t.copy()
    SubMembers["power.lock"] = spinlock_t.copy()
    SubMembers["power.completion.wait.lock"] = spinlock_t.copy()

    SubMembers["devres_head"] = listhead_t.copy()
    SubMembers["dma_pools"] = listhead_t.copy()
    SubMembers["power.entry"] = listhead_t.copy()

    # TODO: some members may not present. needs to purge them if not presented
    PaddingList = { 
#            "coherent_dma_mask":None,
#            "power.max_time_suspended_ns":"CONFIG_PM_RUNTIME",
#            "power.suspend_time":"CONFIG_PM_RUNTIME",
            }

    def __init__(self,name,oplist):
        super().__init__(name,oplist)
        self.populate_oplist()

        # msm has an extra member in archdata
        if name == "msm":
            self.oplist.set_option("(archdata.dma_ops)",force=True)
        else:
            self.oplist.set_option("(archdata.dma_ops)",False,force=True)



    # ugly options initialization
    def populate_oplist(self):
        
        # CONFIG_NUMA doesn't apply for ARM structure even if the option exists

        OptionList.Op.FullOp(self, "SMP", ["mutex.wait_list","mutex.__end_mutex__"], 4, ["mutex.owner"], tradable = ['DEBUG_MUTEXES'])
        OptionList.Op.FullOp(self, "DEBUG_MUTEXES", ["mutex.wait_list", "mutex.__end_mutex__"], 12, ["mutex.owner","mutex.name","mutex.magic"])

        OptionList.Op.FullOp(self, "PINCTRL", ["pm_domain","dma_mask"], 4, ["pins"])
        OptionList.Op.FullOp(self, "CMA", ["dma_mem","archdata"], 4, ["cma_area"])
        OptionList.Op.FullOp(self, "(archdata.dma_ops)", ["archdata","of_node"], 4, ["dma_ops"])

        OptionList.Op.FullOp(self, "PM_SLEEP", ["power.entry","power.should_wakeup"], 24,
                ["power.entry","power.completion","power.wakeup","power.wakeup_path"], antimems=["power.should_wakeup"])

        subs = StructDevice.Members[ StructDevice.Members.index("power.suspend_timer"): StructDevice.Members.index("power.pq_req")+1 ] 
        OptionList.Op.FullOp(self, "PM_RUNTIME", ["power.suspend_timer","power.subsys_data"],120,subs) 

        OptionList.Op.FullOp(self,"DMABOUNCE", ["dma_mem", "of_node"] , 4, ["archdata.dmabounce"] )
        OptionList.Op.FullOp(self,"IOMMU_API", ["dma_mem", "of_node"] , 4, ["archdata.iommu"] )

        OptionList.Op.FullOp(self,"TIMER_STATS", ["power.suspend_timer", "power.timer_expires"], 24, [], deps = ["PM_RUNTIME"])

        # spinlock_t complications
        # lockdep_map: 8+4*(2)  CONFIG_LOCK_STAT:+8
        # appearance: DEBUG_LOCK_ALLOC: spinlock_t, mutex.dep_map, LOCKDEP: two in power
        spinlock_subs = ["devres_lock.", "mutex.wait_lock.", "power.lock."]
        extra_spinlocks=[
            ["power.wait_queue", "power.usage_count"]
        ]
        for par in spinlock_subs:
            bound = [par+"rlock.raw_lock", par+"__end_spinlock__"]
            OptionList.Op.FullOp(self, "GENERIC_LOCKBREAK", bound, 4, [] )
            OptionList.Op.FullOp(self, "DEBUG_SPINLOCK", bound, 16, [])
            OptionList.Op.FullOp(self, "SMP", bound, 4, [], tradable = ["DEBUG_SPINLOCK"])
            OptionList.Op.FullOp(self, "DEBUG_LOCK_ALLOC", bound, 16, [])
            OptionList.Op.FullOp(self, "LOCK_STAT", bound, 8, [], deps = ["DEBUG_LOCK_ALLOC"])
        bound = ["power.completion.wait.lock.rlock.raw_lock","power.completion.wait.lock.__end_spinlock__"]
        OptionList.Op.FullOp(self, "GENERIC_LOCKBREAK", bound, 4, [] ,deps = ["PM_SLEEP"])
        OptionList.Op.FullOp(self, "DEBUG_SPINLOCK", bound, 16, [], deps = ["PM_SLEEP"])
        OptionList.Op.FullOp(self, "SMP", bound, 4, [], tradable = ["DEBUG_SPINLOCK"], deps = ["PM_SLEEP"])
        OptionList.Op.FullOp(self, "DEBUG_LOCK_ALLOC", bound, 16, [], deps = ["PM_SLEEP"])
        OptionList.Op.FullOp(self, "LOCK_STAT", bound, 8, [], deps = ["DEBUG_LOCK_ALLOC"])
        for bound in extra_spinlocks:
            OptionList.Op.FullOp(self, "GENERIC_LOCKBREAK", bound, 4, [], deps = ["PM_RUNTIME"])
            OptionList.Op.FullOp(self, "DEBUG_SPINLOCK", bound, 16, [], deps = ["PM_RUNTIME"])
            OptionList.Op.FullOp(self, "SMP", bound, 4, [], deps = ["PM_RUNTIME"])
            OptionList.Op.FullOp(self, "DEBUG_LOCK_ALLOC", bound, 16, [], deps = ["PM_RUNTIME"])
            OptionList.Op.FullOp(self, "LOCK_STAT", bound, 8, [], deps = ["DEBUG_LOCK_ALLOC"])
        OptionList.Op.FullOp(self, "DEBUG_LOCK_ALLOC", ["mutex.magic", "bus"], 16, [])
        OptionList.Op.FullOp(self, "LOCK_STAT", ["mutex.magic", "bus"], 8, [], deps = ["DEBUG_LOCK_ALLOC"])

        lockdeps_LOCKDEP = [
            ["power.suspend_timer", "power.timer_expires"],
            ["power.work", "power.wait_queue"]
        ]
        
        # add lockdep_map ops
        for rg in lockdeps_LOCKDEP:
            OptionList.Op.FullOp(self, "LOCKDEP", rg, 16, [], deps = ["PM_RUNTIME"])
            OptionList.Op.FullOp(self, "LOCK_STAT", rg, 8, [], deps = ["LOCKDEP"])
        # finished adding options

        #print(self.oplist.ops)

#===========================================================


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
            
            f_esil_str = esil_str(ret[0]['offset'])
            print(f_esil_str)
            ret = r2.cmd(f_esil_str).strip()
            if len(ret)<=2:
                print("no esil found, esil: {}".format(f_esil_str))
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
    if direct_check_op(r2, struct, "sym.kmem_cache_alloc_trace", "CONFIG_TRACING"):
        tarfuncsubs[1][0] += "_trace"
    funclist = FuncRange(tarfunc,tarfuncsubs)
    anal_tar_func(r2,r2_id,funclist)
    _,rg = get_search_range_i2c_0(r2,r2_id,funclist)

    esil_search = "r4,+,0xffffffff,&,=[4]"
    # TODO: change here!!!!!
    reg_proc = lambda item: int( item['code'][0:item['code'].find(esil_search)].split(',')[-2] ,16)
    #reg_proc = lambda item: int(item['code'].split(',')[1],16)
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
    return struct.map_list(ret, ls)


def process_device_resume(r2, r2_id, struct):
    print ("processing device_resume...")
    ls = ['power.is_prepared','pm_domain','type','class','bus','driver','mutex']
    tarfunc = "sym.device_resume"
    funclist = FuncRange(tarfunc,None)
    anal_tar_func(r2,r2_id,funclist)
    rg = get_search_range_device_resume(r2,r2_id,funclist)
    if rg[0]==-1:
        # function not present
        return True
    
    iters = esil_exec_all_branch(r2,rg,rg[0])
    ret = iters("r0")
    while ret[0]==False:
        ret = iters("r0")
    ret = ret[1]
    ret.sort()
    prt_ret = [hex(x) for x in ret]
    return struct.map_list(ret,ls)


# detect __raw_spin_lock_init => CONFIG_DEBUG_SPINLOCK
# detect leaf function => CONFIG_PM_SLEEP not set!!!!

def process_device_initialize(r2, r2_id, struct):
    print("processing device_initialize...")
    ls = ["devres_head.next","devres_head.prev", "dma_pools.next","dma_pools.prev"]
    if r2_id == "vanilla":
        ls+= ["kobj"]
    tarfunc = "sym.device_initialize"
    funclist = FuncRange(tarfunc,None)
    anal_tar_func(r2,r2_id,funclist)
    rg, rgs = get_search_range_device_initialize(r2,r2_id,funclist)

    # hard coded option recovery. ugly as hell
    refs = [hex(x["to"]) for x in json.loads(r2.cmd("s "+tarfunc+"; afxj").strip()) if x["type"]=="call"] # get all func calls
    ref_funcs = [r2.cmd("?w "+ref).strip().split(' ')[1].strip() for ref in refs]

    runtime_flag = False
    spinlock_flag = False

    direct_check_op(r2, struct, "sym.lockdep_init_map", "CONFIG_LOCKDEP",force=True)
    if direct_check_op(r2, struct, "sym.pm_runtime_init", "CONFIG_PM_RUNTIME",force=True):
        runtime_flag = True
    if direct_check_op(r2, struct, "sym.__raw_spin_lock_init", "CONFIG_DEBUG_SPINLOCK",force=True):
        spinlock_flag = True
    direct_check_op(r2, struct, "sym.pm_notifier_call_chain","CONFIG_PM_SLEEP",force=True)

    if not "sym.device_pm_init" in ref_funcs:
        if "sym.complete_all" in ref_funcs:
            ls+= ['power.entry.next','power.entry.prev','power.completion','power.is_prepared','power.power_state','power.wakeup']
        else:
            if not runtime_flag:
                ls+= ['power.power_state', 'power.lock']

    # hard code part end. only deal with first part of the code no matter what.
    ret = []
    iters = esil_exec_all_branch(r2,rgs,rg[0])
    ret = iters("r0")
    print([hex(x) for x in ret[1]])
    ret = ret[1]
    ret.sort()

    if not spinlock_flag: # Else throw an error
        if len(ret)-len(ls)==2:
            ls+=['devres_lock.rlock.dep_map', 'power.lock.rlock.dep_map']
            #struct.oplist.set_option('CONFIG_DEBUG_LOCK_ALLOC')
        if len(ret)-len(ls)==1:
            ls+=['devres_lock.rlock.dep_map']
            #struct.oplist.set_option('CONFIG_DEBUG_LOCK_ALLOC')

    prt_ret = [hex(x) for x in ret]
    ans = struct.map_list(ret,ls)
    if struct.getOffset("devres_lock.rlock.dep_map")!=-1 and struct.getOffset("devres_lock.rlock.dep_map")-struct.getOffset("devres_head.next")==4:
        struct.oplist.set_option("CONFIG_GENERIC_LOCKBREAK",False)
        struct.oplist.set_option("CONFIG_DEBUG_LOCK_ALLOC",False)
    return ans


def process_StructDevice(Msm_r2, Van_r2, Msm_oplist, Van_oplist):
    Struct_vanilla = StructDevice("vanilla", Van_oplist)
    Struct_msm = StructDevice("msm", Msm_oplist)
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

    print("Struct Device analysis done!")
    print("=================================================")
