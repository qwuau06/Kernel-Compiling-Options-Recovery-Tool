########################################
## Members[0: parent, 1: type, ...]
## offsets[0: off_parent, 1: off_type, ...]
## revmap{parent: 0, type: 1, ....}
########################################
UNDEF = -1
ERROR = -2
class StructDevice:
    Members = [
            "parent",
            "p",
            "init_name",
            "kobj",
            "type",
            "mutex",
            "bus",
            "driver",
            "platform_data",
            "power",
            "pm_domain",
            "numa_node",
            "dma_mask",
            "coherent_dma_mask",
            "dma_parms",
            "dma_pools",
            "dma_mem",
            "archdata",
            "of_node",
            "dev_t",
            "id",
            "devres_lock",
            "devres_head",
            "knode_class",
            "class",
            "groups",
            "dev",
            "__end__"
            ]
    SubMembers = {}
    SubMembers["power"] = [
            "power_state",
            "can_wakeup",
            "async_suspend",
            "is_prepared",
            "is_suspended",
            "ignore_children",
            "lock",
            "entry",
            "completion",
            "wakeup",
            "wakeup_path",
            "should_wakeup",
            "suspend_timer",
            "timer_expires",
            "work",
            "wait_queue",
            "usage_count",
            "child_count",
            "disable_depth",
            "idle_notification",
            "request_pending",
            "deferred_resume",
            "run_wake",
            "runtime_auto",
            "no_callbacks",
            "irq_safe",
            "use_autosuspend",
            "timer_autosuspends",
            "request",
            "runtime_status",
            "runtime_error",
            "autosuspend_delay",
            "last_busy",
            "active_jiffies",
            "suspend_jiffies",
            "accounting_timestamp",
            "suspend_time",
            "max_time_suspended_ns",
            "pq_req",
            "subsys_data",
            "constraints"
            ]
    Options = []
    complete = False

    def __init__(self,name):
        self.name = name
        if not StructDevice.complete:
            StructDevice.init_members()
        self.offsets = [UNDEF]*len(StructDevice.Members) # offsets of each member
        self.offsets[0] = 0 # parent is always the first member
        self.revmap = {} # map from name to index
        for idx, item in enumerate(StructDevice.Members):
            self.revmap[item] = idx

    def init_members():
        print("initializing member list...")
        for item in StructDevice.SubMembers.keys():
            for sub in StructDevice.SubMembers[item]:
                sub = item+'.'+sub
                StructDevice.Members.insert(StructDevice.Members.index(item), sub)
            StructDevice.Members.remove(item)
        StructDevice.complete = True
        print("initialization done.")

    def getIndex(self,member):
        try:
            major = member.split('.')[0]
            return self.revmap[member]
        except KeyError:
            print("{} KeyError: Member {} not exist in struct.".format(self.name,member))
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
        return self.__getOffsetById(self.getIndex(name))

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
                return True
        except:
            print("{} IndexError: Try accessing member {} but the total number is {}.".format(self.name,i,len(StructDevice.Members)-1))
            return False

    def __setOffsetByName(self,name, off):
        return self.__setOffsetById(self.getIndex(name), off)

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

    def cmp(self,another):
        diff = 0
        lastmem = "__beginning__"
        for idx, item in enumerate(StructDevice.Members):
            a = self.getOffset(idx)
            b = another.getOffset(idx)

            # both not defined
            if (a == UNDEF and b == UNDEF):
                print("Skipping...: {} not tested.".format(item))
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
                print("possible missing members in {} kernel, between {} and {}, size {}.".format(
                    missing, StructDevice.Members[idx-1], StructDevice.Members[idx],abs(diff)))
                lastmem = item

    def suggest(self):
        # TODO
        None

    def map_list(self,offs, mems):
        if len(offs) != len(mems):
            print("Error: list size mismatch between struct members and returned members")
            return False
        mems.sort(key=lambda x: self.getIndex(x))
        for idx, mem in enumerate(mems):
            off = offs[idx]
            if not self.setOffset(mem, off):
                return False
        return True


