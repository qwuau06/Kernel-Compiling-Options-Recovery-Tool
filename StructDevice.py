#########################################
## Members[0: parent, 1: type, ...]
## offsets[0: off_parent, 1: off_type, ...]
## revmap{parent: 0, type: 1, ....}
########################################
import itertools

#########################
#     Struct Device     #
# ##################### #
# #     OptionList    # #
# # ################# # #
# # #     ########### # #
# # #     # Effect ## # #
# # #     ########### # #
# # # Op  # Effect ## # #
# # #     ########### # #
# # #     # Effect ## # # 
# # #     ########### # #
# # ################# # #
# # #     ########### # # 
# # #     # Effect ## # #
# # #     ########### # #
# # # Op  # Effect ## # #
# # #     ########### # #
# # #     # Effect ## # # 
# # #     ########### # #
# # ################# # #
# ##################### #
#########################

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
            "numa_node",        # CONFIG_NUMA: 4 # not applicable
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
            "dmabounce",        # 4
            "iommu",            # 4
            ]
    spinlock_t = [                  #### spinlock_t model
            "rlock.raw_lock",       # CONFIG_DEBUG_SPINLOCK || CONFIG_SMP: 4
            "rlock.break_lock",     # CONFIG_GENERIC_LOCKBREAK: 4
            "rlock.magic",          # CONFIG_DEBUG_SPINLOCK: 4
            "rlock.owner_cpu",      # CONFIG_DEBUG_SPINLOCK: 4
            "rlock.owner",          # CONFIG_DEBUG_SPINLOCK: 4
            "rlock.dep_map",        # CONFIG_DEBUG_LOCK_ALLOC: lockdep_map
            "__end_spinlock__"
            ]
    listhead_t = [
            "next",
            "prev"
            ]
    SubMembers["devres_lock"] = spinlock_t.copy()
    SubMembers["mutex.wait_lock"] = spinlock_t.copy()
    SubMembers["power.lock"] = spinlock_t.copy()
    SubMembers["power.completion.wait.lock"] = spinlock_t.copy()

    SubMembers["devres_head"] = listhead_t.copy()
    SubMembers["dma_pools"] = listhead_t.copy()
    SubMembers["power.entry"] = listhead_t.copy()

    PaddingList = [
            "dma_pools",
            "devres_head",
            "coherent_dma_mask",
            "power.lock",
            "power.completion.wait.task_list",
            "mutex.wait_list",
            "power.suspend_time",
            "kobj.entry"
            ]

    def range_in_range(a,b):
        ar = [StructDevice.getIndex(a[0]), StructDevice.getIndex(a[1])]
        br = [StructDevice.getIndex(b[0]), StructDevice.getIndex(b[1])]
        if ERROR in ar or ERROR in br:
            exit()
        if ar[0]>=br[0] and ar[1]<=br[1]:
            return True
        else:
            return False
    
    def __init__(self,name):
        self.name = name
        if not StructDevice.initialized:
            StructDevice.init_members()
        self.offsets = [UNDEF]*len(StructDevice.Members) # offsets of each member
        self.offsets[0] = 0 # parent is always the first member
        self.oplist = OptionList(name)

    def init_members():
        print("initializing member list...")
        while len(StructDevice.SubMembers.keys())>0:
            for item in StructDevice.SubMembers.keys():
                if item not in StructDevice.Members:
                    continue
                for sub in StructDevice.SubMembers[item]:
                    sub = item+'.'+sub
                    StructDevice.Members.insert(StructDevice.Members.index(item), sub)
                StructDevice.Members.remove(item)
                first = item+'.'+StructDevice.SubMembers[item][0]
                StructDevice.Members.insert(StructDevice.Members.index(first), item)
                StructDevice.SubMembers[item] = None
            StructDevice.SubMembers = {x:y for x,y in StructDevice.SubMembers.items() if y!=None}
        StructDevice.initialized = True
        for idx, item in enumerate(StructDevice.Members):
            StructDevice.Revmap[item] = idx
        print("initialization done.")
        print(StructDevice.Members)

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

            # deal with padding difference
            if item in StructDevice.PaddingList:
                newdiff = diff
                if diff!=0:
                    if diff > 0:
                        newdiff = diff//8*8
                    elif diff < 0:
                        newdiff = diff//(-8)*(-8)
                    diff = newdiff
                print("Smooth out padding at {}, old diff: {}, new diff: {}.".format(item,diff,newdiff))

            # both not defined
            if (a == UNDEF and b == UNDEF):
                #print("Skipping...: {} not tested.".format(item))
                continue

            # only one has a member
            if (a == UNDEF and b != UNDEF) or (a !=UNDEF and b == UNDEF):
                t = self 
                s = another
                if (a==UNDEF):
                    t = another
                    s = self
                print("{} has member {} that {} doesn't.".format(t.name, item, s.name))
                continue

            # both have a member but with different offsets
            new_diff = a-b
            if diff!=new_diff:
                diff, new_diff = new_diff, new_diff-diff
                if new_diff<0:
                    missing = self.name
                else:
                    missing = another.name
                last_idx = idx-1
                while last_idx>=0 and (self.offsets[last_idx]==UNDEF or another.offsets[last_idx]==UNDEF):
                    last_idx = last_idx-1
                print("possible missing members in {} kernel, between {} and {}, offsets: {}, {}.".format(
                    missing, StructDevice.Members[last_idx], StructDevice.Members[idx],hex(a),hex(b)))
                lastmem = item
                Diff(new_diff,tuple((StructDevice.Members[last_idx], StructDevice.Members[idx])),oplist = self.oplist)
            else:
                print("member registered in both kernel: {}, offset {}, {}.".format(StructDevice.Members[idx],hex(a), hex(b)))
        self.oplist.analyze_between(another)

    def map_list(self,offs, mems):
        if len(offs) != len(mems):
            print("Error: list size mismatch between struct members and returned members")
            return False
        mems.sort(key=lambda x: StructDevice.getIndex(x))
        offs.sort()
        print("Found matches: {}, mapping to {}".format([hex(x) for x in offs],mems))
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
        Cfg = "CONFIG_"
        Verbose = False
        class Effect:
            def __init__(self, opname, extrabytes, extramems, deps, antimems,tradable):
                self.opname = opname
                self.bytes = extrabytes
                self.mems = extramems
                self.deps = deps # only the most direct dep. chains of deps aren't recorded, all deps in parallel
                self.antimems = antimems
                self.children = []
                self.tradable = tradable

            def __repr__(self):
                ret = "Info:"
                ret+= "  bytes:{}\n".format(self.bytes)
                ret+= "  mems:{}\n".format(self.mems)
                ret+= "  deps:{}\n".format(self.deps)
                ret+= "  antimems:{}\n".format(self.antimems)
                children = [x.name for x in self.children]
                ret+= "  children:{}\n".format(children)
                return ret

        def __init__(self, struct, name, bound, extrab, extram, deps=[], antimems = [],tradable = [] ):
            name = OptionList.Op.Cfg+name
            existed = [x for x in struct.ops if x.name == name]
            if len(existed)>0:
                self = existed[0]
            else:
                struct.ops.append(self)
                self.name = name
                # {[bound]:{extramems, extrabytes, subs}}
                self.effects = {}

                self.set = False
                self.verified = False
                self.suspected = False

            deps = [OptionList.Op.Cfg+x for x in deps]
            tradable = [OptionList.Op.Cfg+x for x in tradable]
            for item in deps:
                pars = [x for x in struct.ops if x.name==item]
                if len(pars)==0:
                    print("Error: {} doesn't exist in the list yet.".format(item))
                    exit()
                elif len(pars)>1:
                    print("Error: {} has more than one copy in the list.".format(item))
                    exit()
                par = pars[0]
                # insert children
                for pareffbd in par.effects.keys():
                    for bd in self.effects.keys():
                        if StructDevice.range_in_range(bd,pareffbd):
                            if self not in par.effects[pareffbd].children:
                                par.effects[pareffbd].children.append(self)
                            break

            # add new effect into dict
            self.effects[tuple((bound))] = OptionList.Op.Effect(name, extrab, extram, deps, antimems,tradable)

        def __repr__(self):
            ret = "\n\n{}:".format(self.name)
            if OptionList.Op.Verbose:
                for rg,eff in self.effects.items():
                    ret+=" {}:".format(rg)
                    ret+=eff.__repr__()
            else:
                for rg,eff in self.effects.items():
                    ret+=" \n{}: {}+extra:{}".format(rg, eff.bytes, [x.name for x in eff.children])
            return ret

        # get corresponding effect to a bound
        def get_eff(self,bounds):
            for effbd,eff in self.effects.items():
                if StructDevice.range_in_range(effbd, bounds):
                    return eff
            #print("Error: Didn't find {} with in {}.".format(bounds, self.name))
            return None

    # ugly options initialization
    def __init__(self,name):
        self.name = name
        self.ops = []
        # CONFIG_NUMA doesn't apply for ARM structure even if the option exists

        OptionList.Op(self, "SMP", ["mutex.wait_list","mutex.__end_mutex__"], 4, ["mutex.owner"], tradable = ['DEBUG_MUTEXES'])
        OptionList.Op(self, "DEBUG_MUTEXES", ["mutex.wait_list", "mutex.__end_mutex__"], 12, ["mutex.owner","mutex.name","mutex.magic"])

        OptionList.Op(self, "PM_SLEEP", ["power.entry","power.should_wakeup"], 28-4, 
                ["power.entry","power.completion","power.wakeup","power.wakeup_path"], antimems=["power.should_wakeup"])

        subs = StructDevice.Members[ StructDevice.Members.index("power.suspend_timer"): StructDevice.Members.index("power.pq_req")+1 ] 
        OptionList.Op(self, "PM_RUNTIME", ["power.suspend_timer","power.subsys_data"],120,subs) 

        OptionList.Op(self,"DMABOUNCE", ["dma_mem", "of_node"] , 4, ["archdata.dmabounce"] )
        OptionList.Op(self,"IOMMU_API", ["dma_mem", "of_node"] , 4, ["archdata.iommu"] )

        OptionList.Op(self,"TIMER_STATS", ["power.suspend_timer", "power.timer_expires"], 24, [], deps = ["PM_RUNTIME"])

        # spinlock_t complications
        spinlock_subs = ["devres_lock.", "mutex.wait_lock.", "power.lock.", "power.completion.wait.lock."]
        extra_spinlocks=[
            ["power.wait_queue", "power.usage_count"]
        ]
        for par in spinlock_subs:
            bound = [par+"rlock.raw_lock", par+"__end_spinlock__"]
            OptionList.Op(self, "GENERIC_LOCKBREAK", bound, 4, [], deps = ["PM_RUNTIME"])
            OptionList.Op(self, "DEBUG_SPINLOCK", bound, 16, [], deps = ["PM_RUNTIME"])
            OptionList.Op(self, "SMP", bound, 4, [], tradable = ["DEBUG_SPINLOCK"], deps = ["PM_RUNTIME"])
        for rg in extra_spinlocks:
            OptionList.Op(self, "GENERIC_LOCKBREAK", rg, 4, [])
            OptionList.Op(self, "DEBUG_SPINLOCK", rg, 16, [])
            OptionList.Op(self, "SMP", rg, 4, [])

        # lockdep_map: 8+4*(2)  CONFIG_LOCK_STAT:+8
        # appearance: DEBUG_LOCK_ALLOC: spinlock_t, mutex.dep_map, LOCKDEP: two in power

        # generate list
        lockdeps_LOCKDEP = [
            ["power.suspend_timer", "power.timer_expires"],
            ["power.work", "power.wait_queue"]
        ]
        lockdeps_DEBUG_LOCK_ALLOC = [
            ["mutex.magic", "mutex.__end_mutex__"] 
        ]
        for parent in spinlock_subs:
            tmp = [parent+"rlock.owner", parent+"__end_spinlock__"]
            lockdeps_DEBUG_LOCK_ALLOC.append(tmp)
        for bound in extra_spinlocks:
            lockdeps_DEBUG_LOCK_ALLOC.append(bound)

        # add lockdep_map ops
        for rg in lockdeps_LOCKDEP:
            OptionList.Op(self, "LOCKDEP", rg, 16, [], deps = ["PM_RUNTIME"])
            OptionList.Op(self, "LOCK_STAT", rg, 8, [], deps = ["LOCKDEP"])
        for rg in lockdeps_DEBUG_LOCK_ALLOC:
            OptionList.Op(self, "DEBUG_LOCK_ALLOC", rg, 16, [], deps = ["PM_RUNTIME"])
            OptionList.Op(self, "LOCK_STAT", rg, 8, [], deps = ["DEBUG_LOCK_ALLOC"])
        # finished adding options

        #print(self.ops)

    def set_option(self, opname, val=True, suspected = False):
        if opname not in [o.name for o in self.ops]:
            print ("Error: non-existing option!")
            exit()
        op = self.get_option(opname)
        if op.verified==True and op.set != val:
            print("Error: conflicting options: {}".format(op))
            exit()
        oldval = op.set
        op.set=val
        op.verified=True
        op.suspected = suspected

    def get_option(self, opname):
        t = [x for x in self.ops if x.name==opname]
        if len(t)==0:
            print("Error: unknown option {}.".format(opname))
        return t[0]

    # core function
    # this function is only used from vanilla to msm, diff is offset of msm-vanilla
    # in case of offset difference
    # three cases of options:
    # case 1: both not set
    # case 2: one set, one not set: this case results in diffs
    # case 3: both set: seems same as 1, but this causes possible dependency problems and large changes in offsets
    # analyze:
    # possible cases of options regarding to diff
    # case 1: no option availabe, but size different: undetectable, only report difference
    # case 2: only one option: if match then return, otherwise undetectable
    # case 3: more than one option and only one option or a certain combination can satisfy the offset (minimum, due to padding smoothing out)
    # case 3: more than one option and cannot decide: powerset over all possibilities, calc offset for each. find the most relateable one

    def analyze_between(self, another):
        another = another.oplist
        diff_list = Diff.diff_list
        Diff.pos_oplist = self
        Diff.neg_oplist = another
        print("=================================================")
        print("Diff list: {}".format(len(diff_list)))

        Diff.update_diffs()

        #dry_list = self.ops
        a_list = self.ops
        b_list = another.ops
        print("Start analysis...")
        ret = []
        diff_assert = lambda x:ret.append("Detected difference [{}, {}], size {}.".format(x.bounds[0],x.bounds[1],x.diff))
        must_op_str = lambda x,who:ret.append("{}: {} True.".format(who.name,x.name))
        poss_op_str = lambda x,who:ret.append("{}: {} Potentially True.".format(who,x))
        none_op_str = lambda x,who:ret.append("{}: {} False.".format(who.name,x.name))
        unkn_op_str = lambda x:ret.append("Unknown Option between {} and {}, size {}.".format(x.bounds[0],x.bounds[1],x.diff))

        # Round 1: remove known options:
        for op in a_list:
            if op.verified and not op.suspected:
                if op.set:
                    must_op_str(op,self)
                else:
                    none_op_str(op,self)
        for op in b_list:
            if op.verified and not op.suspected:
                if op.set:
                    must_op_str(op,another)
                else:
                    none_op_str(op,another)
        Diff.update_diffs()

        # Round 2: no options. If there's a difference then it is an unknown tag
        for diff in diff_list:
            diff_assert(diff)
            if len(diff.oplist)==0: # no options
                unkn_op_str(diff)
        # Round 3: only has one option and size matches:
            elif len(diff.oplist)==1:   # one option
                opname = diff.oplist[0]
                op_a = self.get_option(opname)
                op_b = another.get_option(opname)
                # TODO: currently we assume op_a == op_b so we let op = op_a
                if op_a.get_bytes() == abs(diff.diff):
                    if diff.diff >0:
                        op = op_a
                        st = self
                    else:
                        op = op_b
                        st = another
                    must_op_str(op,st)
                    #diff.expected += op.get_bytes()
                    op.verified = True
                    op.set = True
                    if len(eff.deps)==1:
                        op = eff.deps[0]
                        op.verified = True
                        op.set = True
                else:
                    unkn_op_str(diff)
        # Round 4: more than 2 options but only one option is below diff
            else:
                # TODO: remove self ref, and the implication of same options
                # print(diff.oplist)
                opnames = [op for op in diff.oplist if diff.get_bytes(self.get_option(op))>0 and  diff.get_bytes(self.get_option(op))<=abs(diff.diff)]
                if len(opnames)==1:
                    sign = 1
                    if diff.diff >0:
                        st = self
                        sign = 1
                    else:
                        st = another
                        sign = -1
                    op = st.get_option(opnames[0])
                    must_op_str(op,st)
                    #diff.expected += sign*diff.get_bytes(self.get_option(op))
                    op.verified = True
                    op.set = True
        Diff.update_diffs()

        if Diff.saturated():
            for item in ret:
                print(item)
            return ret 

        # Eradicated enough cases, now need to run a powerset
        # diff_list = [x for x in diff_list if x.expected != x.diff]
        a_dep_list = [x for x in a_list if x.verified and x.set and not x.suspected] # sure existing members
        b_dep_list = [x for x in b_list if x.verified and x.set and not x.suspected] # sure existing members

        a_list = []
        b_list = []
        print("Populating perm lists")
        for diff in Diff.diff_list:
            for opname in diff.oplist:
                a_op = self.get_option(opname)
                b_op = another.get_option(opname)
                if a_op not in a_list and not(a_op.verified and not a_op.set) and a_op not in a_dep_list:
                    a_list.append(a_op)
                if b_op not in b_list and not(b_op.verified and not b_op.set) and b_op not in b_dep_list:
                    b_list.append(b_op)
        print(Diff.diff_list)
                
        print("first round eradication done.")
        print("dry list a len:{}".format(len(a_list)))
        print("dry list b len:{}".format(len(b_list)))
        print("dep list a len:{}".format(len(a_dep_list)))
        print("dep list b len:{}".format(len(b_dep_list)))
        print("dry list a:{}".format( [x.name for x in a_list] ))
        print("dry list b:{}".format( [x.name for x in b_list] ))

        # making the powerset
        a_perms = list(powerset(a_list))
        b_perms = list(powerset(b_list))
#        for y in a_perms:
#            print([x.name for x in y])
#        for y in b_perms:
#            print([x.name for x in y])
        perms = []
#        for perms in [a_perms, b_perms]:
#            for perm in perms:
#                flag = True
#                # for each member, if it has dependencies and none of dependencies show up in the case, it isn't practical then
#                for op in perm:
#                    if (len(item.parents)>0 and
#                    len(list(set(item.parents).intersection(perm)))==0 and
#                    len(list(set(item.parents).intersection(dep_list)))==0):
#                        flag = False
#                if flag:
#                    perms.append(perm)
        for a in a_perms:
            for b in b_perms:
                list1= [x.name for x in a]
                list2 = [x.name for x in b]
                if len(list(set(list1).intersection(list2)))>0:
                    continue
                perms.append({'a':a, 'b':b})
        print("all permutations: {}.".format(len(perms)))

#        for item in perms:
#            a_ops = [x.name for x in item['a']]
#            b_ops = [x.name for x in item['b']]
#            print("{};{}".format(a_ops,b_ops))

        # core code for config permutation
        res_out = {}
        for perm in perms:
            flattened_perm = tuple(( [*[self.name+"."+op.name for op in perm['a']],*[another.name+"."+op.name for op in perm['b']]  ]   ))
            for op in [*perm['a'],*perm['b']]:
                op.suspected = True
                op.verified = True
                op.set = True
            Diff.update_diffs()
            # add into dict
            total_diff = 0
            for diff in diff_list:
                total_diff += abs(diff.diff-diff.expected)
            res_out[flattened_perm] = total_diff
            # clean up
            for op in [*perm['a'],*perm['b']]:
                op.suspected = False
                op.verified = False
                op.set = False
            Diff.update_diffs()

        thres = 100
        maxcount = 10
        case = 0
        Diff.diff_list.append(self)
        for perm, res in sorted(res_out.items(),key=lambda kv:kv[1] ):
            if res == 0:
                ret.append("\nExact matching case {}:".format(case))
            elif res > thres:
                continue
            else:
                ret.append("\nNon-exact matching case {}, total abs diff {}:".format(case,res))
            for op in perm:
                names = op.split('.')
                poss_op_str(names[1],names[0])
            case += 1
            if case > maxcount:
                break

        for item in ret:
            print(item)
        return ret

# Diff between two list of offsets, and corresponding options
# Notice that it isn't tied to any specific StructDevice; it's independent
class Diff:
    diff_list = []
    pos_oplist = None
    neg_oplist  = None
    
    def __init__(self, diff, bounds, oplist=None):
        self.diff = diff        # diff
        self.bounds = bounds    # (lower, upper)
        self.oplist = [] # notice it only register the names
        self.expected = 0
        self.get_eff = lambda o: o.get_eff(self.bounds)
        self.get_bytes = lambda o: o.get_eff(self.bounds).bytes if o.get_eff(self.bounds)!=None else -1
        Diff.diff_list.append(self)
        if oplist:
            for op in oplist.ops:
                if self.option_in_range(op):
                    self.oplist.append(op.name)
            
                
    def option_in_range(self, option):
        opbound = option.effects.keys()
        for opbd in opbound: # self bound inside bd
            if StructDevice.range_in_range(opbd,self.bounds):
                return True
        return False

    def __repr__(self):
        #opls = [y.name for y in self.oplist for x in OptionList.get_option(y).effects if len(x.deps)==0]
        #opls += ["child:"+y.name for y in self.oplist for x in OptionList.get_option(y).effects if len(x.deps)>0]
        return "\n{}={}:{},{}".format(self.diff,self.expected, self.bounds, self.oplist)

    # update diffs after changes in options.
    # TODO:this function should not depend on struct, but currently doesn't have a better way, unless rewriting it.
    def update_diffs(): 
        if Diff.pos_oplist == None or Diff.neg_oplist == None:
            print("please set positive and negetive structs first")
            exit()
        pos_op = Diff.pos_oplist
        neg_op = Diff.neg_oplist

        for diff in Diff.diff_list:
            diff.expected = 0
        new_list = []
        delete_flag = True
        for op in pos_op.ops:
            if op.verified and op.set:
                for k,v in op.effects.items():
                    get = lambda x: pos_op.get_option(x)
                    # if dep not satisfied
                    if len(v.deps)>0 and  len([x for x in v.deps if get(x).verified and get(x).set])==0:
                        continue
                    # if tradable exists
                    if len(v.tradable)>0 and len([x for x in v.tradable if get(x).verified and get(x).set])>0:
                        continue
                    new_list+= [tuple((k,v.bytes))]
                if op.suspected:
                    delete_flag = False
        for op in neg_op.ops:
            if op.verified and op.set:
                for k,v in op.effects.items():
                    get = lambda x: neg_op.get_option(x)
                    # if dep not satisfied
                    if len(v.deps)>0 and  len([x for x in v.deps if get(x).verified and get(x).set])==0:
                        continue
                    # if tradable exists
                    if len(v.tradable)>0 and len([x for x in v.tradable if get(x).verified and get(x).set])>0:
                        continue
                    new_list+= [tuple((k,-v.bytes))]
                if op.suspected:
                    delete_flag = False
        for item in new_list:
            bounds, extrabytes = item[0],item[1]
            flag = False
            for diff in Diff.diff_list:
                if StructDevice.range_in_range(bounds, diff.bounds):
                    flag = True
                    diff.expected += extrabytes
            if not flag:
                Diff(-extrabytes, bounds, pos_op)
        #print("\nPost update:...")
        #print(Diff.diff_list)
        if delete_flag:
            Diff.diff_list = [x for x in Diff.diff_list if x.diff != x.expected]

    def saturated():
        for diff in Diff.diff_list:
            if diff.expected != diff.diff:
                return False
        return True
