########################################
## Members[0: parent, 1: type, ...]
## offsets[0: off_parent, 1: off_type, ...]
## revmap{parent: 0, type: 1, ....}
########################################
import itertools

UNDEF = -1
ERROR = -2

def powerset(iterable):
    s = list(iterable)
    return itertools.chain.from_iterable(itertools.combinations(s, r) for r in range(len(s)+1))

class StructDevice:
    initialized = False
    Revmap = {}
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
            "numa_node",        # CONFIG_NUMA: 4
            "dma_mask",         # 4
            "coherent_dma_mask",# 8
            "dma_parms",        # 4
            "dma_pools",        # 8
            "dma_mem",          # 4
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
            "__end__"           # 0, placeholder
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
            "completion",       # CONFIG_PM_SLEEP: 12+spinlock_t
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
    SubMembers["knode_class"] = [
            "n_klist",          # 4
            "n_node",           # 8
            "n_ref"             # 4
            ]
    spinlock_t = [                  #### spinlock_t model
            "rlock.raw_lock",       # 4
            "rlock.break_lock",     # CONFIG_GENERIC_LOCKBREAK: 4
            "rlock.magic",          # CONFIG_DEBUG_SPINLOCK: 4
            "rlock.owner_cpu",      # CONFIG_DEBUG_SPINLOCK: 4
            "rlock.owner",          # CONFIG_DEBUG_SPINLOCK: 4
            "rlock.dep_map",         # CONFIG_DEBUG_LOCK_ALLOC: lockdep_map
            "__end_spinlock__"
            ]
    SubMembers["devres_lock"] = spinlock_t.copy()
    SubMembers["mutex.wait_lock"] = spinlock_t.copy()
    SubMembers["power.lock"] = spinlock_t.copy()
    
    def __init__(self,name):
        self.name = name
        if not StructDevice.initialized:
            StructDevice.init_members()
        self.offsets = [UNDEF]*len(StructDevice.Members) # offsets of each member
        self.offsets[0] = 0 # parent is always the first member
        self.oplist = OptionList()

    def init_members():
        print("initializing member list...")
        while len(StructDevice.SubMembers.keys())>0:
            for item in StructDevice.SubMembers.keys():
                if item not in StructDevice.Members:
                    continue
                for sub in StructDevice.SubMembers[item]:
                    sub = item+'.'+sub
                    StructDevice.Members.insert(StructDevice.Members.index(item)+1, sub)
                #StructDevice.Members.remove(item)      # still keep the original member in case it's called. it will be identical to the item
                StructDevice.SubMembers[item] = None
            StructDevice.SubMembers = {x:y for x,y in StructDevice.SubMembers.items() if y!=None}
        StructDevice.initialized = True
        for idx, item in enumerate(StructDevice.Members):
            StructDevice.Revmap[item] = idx
        print("initialization done.")

    def getIndex(member):
        try:
            major = member.split('.')[0]
            return StructDevice.Revmap[member]
        except KeyError:
            print("KeyError: Member {} not exist in struct.".format(member))
            return ERROR

    def __getOffsetById(self,i):
        if i < 0:
            return i
        try:
            return self.offsets[i]
        except IndexError:
            print("{} IndexError: Try accessing member {} but the total number is {}.".format(self.name,i,len(StructDevice.Members)-1))
            return ERROR

    def __getOffsetByName(self,name):
        return self.__getOffsetById(StructDevice.getIndex(name))

    def __setOffsetById(self,i,off):
        if i < 0:
            return False
        try:
            if self.offsets[i] != UNDEF and self.offsets[i] != off:
                print("{} Error: A confliction! {} offset is {} but trying to assign a different value {}.".format(
                    self.name,StructDevice.Members[i],self.getOffset(i),off))
                return False
            else:
                self.offsets[i] = off
                # the first offset of a submember is identical to the member itself
                # may not be vice versa, when it's not clear which member exactly was involved
                if "." in StructDevice.Members[i]:
                    prefix = StructDevice.Members[i].split('.')[0]
                    if StructDevice.Members[i-1] == prefix:
                        self.offsets[i-1] = off
                return True
        except:
            print("{} IndexError: Try accessing member {} but the total number is {}.".format(self.name,i,len(StructDevice.Members)-1))
            return False

    def __setOffsetByName(self,name, off):
        return self.__setOffsetById(StructDevice.getIndex(name), off)

    def getOffset(self,item):
        if isinstance(item, int):
            return self.__getOffsetById(item)
        else:
            return self.__getOffsetByName(item)

    def setOffset(self,item, off):
        if isinstance(item, int):
            return self.__setOffsetById(item,off)
        else:
            return self.__setOffsetByName(item,off)

    # this is run by msm kernel
    def cmp(self,another):
        diff = 0
        diff_list = []
        lastmem = "__beginning__"
        for idx, item in enumerate(StructDevice.Members):
            a = self.getOffset(idx)
            b = another.getOffset(idx)

            # both not defined
            if (a == UNDEF and b == UNDEF):
                #print("Skipping...: {} not tested.".format(item))
                continue

            # only one has a member
            if (a == UNDEF and b != UNDEF) or (a !=UNDEF and b == UNDEF):
                t = a
                s = b
                if (a==UNDEF):
                    t = b
                    s = a
                print("{} has member {} that {} doesn't".format(t.name, item, s.name))
                continue

            # both have a member but with different offsets
            diff = a-b-diff
            if diff!=0:
                if diff<0:
                    missing = self.name
                else:
                    missing = another.name
                last_idx = idx-1
                while last_idx>=0 and self.offsets[last_idx]==UNDEF:
                    last_idx = last_idx-1
                print("possible missing members in {} kernel, between {} and {}, size {}.".format(
                    missing, StructDevice.Members[last_idx], StructDevice.Members[idx],abs(diff)))
                lastmem = item
                diff_list.append(Diff(diff,tuple((StructDevice.Members[last_idx], StructDevice.Members[idx])),self.oplist))
            else:
                print("member registered in both kernel: {}.".format(StructDevice.Members[idx]))
        self.oplist.analyze_between(diff_list)

    def map_list(self,offs, mems):
        if len(offs) != len(mems):
            print("Error: list size mismatch between struct members and returned members")
            return False
        mems.sort(key=lambda x: StructDevice.getIndex(x))
        for idx, mem in enumerate(mems):
            off = offs[idx]
            if not self.setOffset(mem, off):
                return False
        return True



# detection logic:
#   first round: go through all the members. some members are option locked, thus can determine a list of ops
#   second round: for each diff = msm.member_off -  linux.member_off
class OptionList:
    # class of a single option
    class Op:
        def __init__(self, struct, name, bound, extrab, extram ):
            self.name = name
            #for bd in bound:
            #    bd = [StructDevice.getIndex(x) for x in bd]
            self.bound = bound
            self.extrabytes = extrab # by default, a member is not set; if disable it also brings a member, that member would count as default
            self.extramems = extram

            self.set = False
            self.verified = False
            self.suspected = False
            self.exchangable = [] # in case two options both enables a single member
            self.parents = [] # won't appear if the parent isn't set; all members in parallel: any of parents enabled will make it available
            self.antimems = [] # only exist when it's not set
            
            struct.ops.append(self)

        def __repr__(self):
            bound_str = ""
            if len(self.bound)==1:
                bound_str = str(self.bound[0])
            else:
                bound_str = "\n"
                for item in self.bound:
                    bound_str += str(item)+"\n"
            return "\n{}: {}, {}\n".format(self.name,bound_str,self.extrabytes)

    # ugly initialization
    def __init__(self):
        self.ops = []
        cfg = "CONFIG_"

        OptionList.Op(self,cfg+"SMP", [ ["mutex.owner", "mutex.name"] ], 4, [])
        OptionList.Op(self,cfg+"NUMA", [ ["pm_domain","dma_mask"] ],4,["numa_node"])
        tmp = OptionList.Op(self,cfg+"PM_SLEEP",[ ["power.lock","power.subsys_data"] ], 33-4, 
                ["power.entry","power.completion","power.wakeup","power.wakeup_path","power.pq_req"])# remove the anti-member difference 
        tmp.antimems = ["power.should_wakeup"]
        OptionList.Op(self,cfg+"PM_RUNTIME",[ ["power.lock","power.subsys_data"] ],124,[]) # list too long and no need to finish for now
        OptionList.Op(self,cfg+"DMABOUNCE", [ ["dma_mem", "of_node"] ], 4, [] )
        OptionList.Op(self,cfg+"IOMMU_API", [ ["dma_mem", "of_node"] ], 4, [] )

        OptionList.Op(self,cfg+"DEBUG_MUTEXES", [ ["mutex.wait_list", "mutex.__end_mutex__"] ], 12, ["mutex.owner","mutex.name","mutex.magic"])
        tmp = OptionList.Op(self,cfg+"TIMER_STATS", [ ["power.suspend_timer", "power.timer_expires"] ], 24, [])
        tmp.parent = [cfg+"CONFIG_PM_RUNTIME"]

        # spinlock complication
        t0 = OptionList.Op(self,cfg+"GENERIC_LOCKBREAK", [ ["rlock.break_lock","__end_spinlock__"] ], 4, [])
        t1 = OptionList.Op(self,cfg+"DEBUG_SPINLOCK", [ ["rlock.break_lock","__end_spinlock__"] ], 12, [])
        t = [t0,t1]
        extra_spinlocks=[
            ["power.completion", "power.wakeup"],
            ["power.wait_queue", "power.usage_count"]
        ]
        spinlock_subs = ["devres_lock.", "mutex.wait_lock.", "power.lock."]

        for ts in t:
            lower,upper = ts.bound[0][0], ts.bound[0][1]
            ts.bound = []
            for parent in spinlock_subs:
                tmp = [parent+lower, parent+upper]
                ts.bound.append(tmp)
            ts.bound = ts.bound+extra_spinlocks

        # lockdep_map: 8+4*(2)  CONFIG_LOCK_STAT:+8
        lockdeps_LOCKDEP = [
            ["power.suspend_timer", "power.timer_expires"],
            ["power.work", "power.wait_queue"]
        ]
        tmp = OptionList.Op(self,cfg+"LOCKDEP", lockdeps_LOCKDEP , 16, [])
        tmp.parent = [cfg+"PM_RUNTIME"]

        lockdeps_DEBUG_LOCK_ALLOC = [
            ["mutex.magic", "mutex.__end_mutex__"] 
        ]
        for parent in spinlock_subs:
            tmp = [parent+"rlock.owner", parent+"__end_spinlock__"]
            lockdeps_DEBUG_LOCK_ALLOC.append(tmp)
        for bound in extra_spinlocks:
            lockdeps_DEBUG_LOCK_ALLOC.append(bound)
        
        all_lockdeps = lockdeps_LOCKDEP + lockdeps_DEBUG_LOCK_ALLOC
        OptionList.Op(self,cfg+"DEBUG_LOCK_ALLOC", lockdeps_DEBUG_LOCK_ALLOC, 16, [])
        OptionList.Op(self,cfg+"LOCK_STAT", all_lockdeps, 8, [])
        #print(self.ops)

    def set_option(self, option, val=True):
        if option not in self.ops:
            print ("Error: non-existing option!")
            exit()
        opt = [x for x in self.ops if x.name==option]
        opt = opt[0]
        if opt.verified==True and opt.set != val:
            print("Error: conflicting options: {}".format(option))
            exit()
        opt.set=val
        opt.verified=True

    def hard_reqs(mems):
        ret = []
        for mem in mems:
            for x in OptionList.ops:
                if mem in x.extramems:
                    x.set = True
                if mem in x.antimemes:
                    x.set = False
                x.verified = True
                
    # this function is only used from vanilla to msm, diff is offset of msm-vanilla
    # in case of offset difference
    # case 1: no option availabe, but size different: undetectable, only report difference
    # case 2: only one option: if match then return, otherwise undetectable
    # case 3: more than one option: permuatation over all possibilities, calc offset for each. find the most relateable one

    def analyze_between(self, diff_list):
        print("=================================================")
        print("diff list:")
        for item in diff_list:
            print(item)

        diff_list = [x for x in diff_list if x.expected != x.diff] # remove already satisfied diffs
        dry_list = self.ops
        print("=================================================")
        print("Start analysis...")
        print("Diff list: {}".format(len(diff_list)))
        ret = []
        diff_assert = lambda x:ret.append("Detected difference [{}, {}], size {}.".format(x.bounds[0],x.bounds[1],x.diff))
        must_op_str = lambda x:ret.append("Option {} is enabled.".format(x.name))
        poss_op_str = lambda x:ret.append("Option {} may be enabled".format(x.name))
        none_op_str = lambda x:ret.append("Option {} isn't enabled.".format(x.name))
        unkn_op_str = lambda x:ret.append("Unknown Option between {} and {}, size {}.".format(x.bounds[0],x.bounds[1],x.diff))

        for op in self.ops:
            if op.verified and not op.suspected:
                if op.set:
                    must_op_str(op)
                else:
                    none_op_str(op)

        for diff in diff_list:
            diff_assert(diff)
            if len(diff.oplist)==0: # no options
                unkn_op_str(diff)
            elif len(diff.oplist)==1:   # one option
                op = diff.oplist[0]
                if op.extrabytes == diff.diff:
                    must_op_str(op)
                    diff.expected = op.extrabytes
                    op.verified = True
                    op.set = True
                else:
                    unkn_op_str(diff)
                    none_op_str(op.name)
                    op.verified = True
                    op.set = False
        diff_list = [x for x in diff_list if x.expected != x.diff]
        dep_list = [x for x in dry_list if x.verified and x.set and not x.suspected] # sure existing members
        dry_list = [x for x in dry_list if not (x.verified and not x.suspected)] # remove sure members 

        print("first round eradication done.")
        print("dry list len:{}".format(len(dry_list)))
        print("dep list len:{}".format(len(dep_list)))

        raw_perms = powerset(dry_list)
        perms = []
        for perm in raw_perms:
            flag = True
            # for each member, if it has dependencies and none of dependencies show up in the case, it isn't practical then
            for item in perm:
                if (len(item.parents)>0 and
                len(list(set(item.parents).intersection(perm)))==0 and
                len(list(set(item.parents).intersection(dep_list)))==0):
                    flag = False
            if flag:
                perms.append(perm)
        print("all permutations: {}.".format(len(perms)))

        # core code for config permutation
        res_out = {}
        for perm in perms:
            for op in perm:
                op.suspected = True
                op.verified = True
                op.set = True
            for diff in diff_list:
                for op in perm:
                    if diff.option_in_range(op):
                        diff.expected += op.extrabytes
            # add into dict
            total_diff = 0
            for diff in diff_list:
                total_diff += abs(diff.diff-diff.expected)
            res_out[perm] = total_diff
            # clean up
            for op in perm:
                op.suspected = False
                op.verified = False
                op.set = False
            for diff in diff_list:
                for op in perm:
                    if diff.option_in_range(op):
                        diff.expected -= op.extrabytes

        thres = 8 
        case = 0
        for perm, res in sorted(res_out.items(),key=lambda kv:kv[1] ):
            if res > thres:
                continue
            elif res == 0:
                ret.append("\nExact matching case {}:".format(case))
            else:
                ret.append("\nNon-exact matching case {}, total abs diff {}:".format(case,res))
            for op in perm:
                poss_op_str(op)
            case += 1

        for item in ret:
            print(item)
        return ret


class Diff:
    def __init__(self, diff, bounds, oplist):
        self.diff = diff        # diff
        self.bounds = bounds    # (lower, upper)
        self.oplist = []
        self.expected = 0
        for op in oplist.ops:
            if self.option_in_range(op):
                self.oplist.append(op)
                if op.verified and not op.suspected:
                    self.expected = op.extrabytes * op.set # 0 or extrabytes
                
    def option_in_range(self, option):
        opbound = option.bound
        bi = lambda x:StructDevice.getIndex(x)
        for bd in opbound: # self bound inside bd
            if bi(self.bounds[0])<=bi(bd[0]) and bi(self.bounds[1])>=bi(bd[1]):
                return True
        return False

    def __repr__(self):
        opls = [x.name for x in self.oplist if len(x.parents)==0]
        opls += ["child:"+x.name for x in self.oplist if len(x.parents)>1]
        return "{}:{},{}".format(self.diff, self.bounds, opls)
