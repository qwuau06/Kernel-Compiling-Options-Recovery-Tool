from Structs import StructBase, OptionList

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

    # TODO: some members may not present. needs to purge them if not presented
    PaddingList = { 
#            "coherent_dma_mask":None,
#            "power.max_time_suspended_ns":"CONFIG_PM_RUNTIME",
#            "power.suspend_time":"CONFIG_PM_RUNTIME",
            }

    def __init__(self,name):
        super().__init__(name)
        self.populate_oplist()

        # msm has an extra member in archdata
        if name == "msm":
            self.oplist.set_option("(archdata.dma_ops)",force=True)
        else:
            self.oplist.set_option("(archdata.dma_ops)",False,force=True)



    # ugly options initialization
    def populate_oplist(self):
        
        # CONFIG_NUMA doesn't apply for ARM structure even if the option exists

        OptionList.Op(self, "SMP", ["mutex.wait_list","mutex.__end_mutex__"], 4, ["mutex.owner"], tradable = ['DEBUG_MUTEXES'])
        OptionList.Op(self, "DEBUG_MUTEXES", ["mutex.wait_list", "mutex.__end_mutex__"], 12, ["mutex.owner","mutex.name","mutex.magic"])

        OptionList.Op(self, "PINCTRL", ["pm_domain","dma_mask"], 4, ["pins"])
        OptionList.Op(self, "CMA", ["dma_mem","archdata"], 4, ["cma_area"])
        OptionList.Op(self, "(archdata.dma_ops)", ["archdata","of_node"], 4, ["dma_ops"])

        OptionList.Op(self, "PM_SLEEP", ["power.entry","power.should_wakeup"], 24,
                ["power.entry","power.completion","power.wakeup","power.wakeup_path"], antimems=["power.should_wakeup"])

        subs = StructDevice.Members[ StructDevice.Members.index("power.suspend_timer"): StructDevice.Members.index("power.pq_req")+1 ] 
        OptionList.Op(self, "PM_RUNTIME", ["power.suspend_timer","power.subsys_data"],120,subs) 

        OptionList.Op(self,"DMABOUNCE", ["dma_mem", "of_node"] , 4, ["archdata.dmabounce"] )
        OptionList.Op(self,"IOMMU_API", ["dma_mem", "of_node"] , 4, ["archdata.iommu"] )

        OptionList.Op(self,"TIMER_STATS", ["power.suspend_timer", "power.timer_expires"], 24, [], deps = ["PM_RUNTIME"])

        # spinlock_t complications
        # lockdep_map: 8+4*(2)  CONFIG_LOCK_STAT:+8
        # appearance: DEBUG_LOCK_ALLOC: spinlock_t, mutex.dep_map, LOCKDEP: two in power
        spinlock_subs = ["devres_lock.", "mutex.wait_lock.", "power.lock."]
        extra_spinlocks=[
            ["power.wait_queue", "power.usage_count"]
        ]
        for par in spinlock_subs:
            bound = [par+"rlock.raw_lock", par+"__end_spinlock__"]
            OptionList.Op(self, "GENERIC_LOCKBREAK", bound, 4, [] )
            OptionList.Op(self, "DEBUG_SPINLOCK", bound, 16, [])
            OptionList.Op(self, "SMP", bound, 4, [], tradable = ["DEBUG_SPINLOCK"])
            OptionList.Op(self, "DEBUG_LOCK_ALLOC", bound, 16, [])
            OptionList.Op(self, "LOCK_STAT", bound, 8, [], deps = ["DEBUG_LOCK_ALLOC"])
        bound = ["power.completion.wait.lock.rlock.raw_lock","power.completion.wait.lock.__end_spinlock__"]
        OptionList.Op(self, "GENERIC_LOCKBREAK", bound, 4, [] ,deps = ["PM_SLEEP"])
        OptionList.Op(self, "DEBUG_SPINLOCK", bound, 16, [], deps = ["PM_SLEEP"])
        OptionList.Op(self, "SMP", bound, 4, [], tradable = ["DEBUG_SPINLOCK"], deps = ["PM_SLEEP"])
        OptionList.Op(self, "DEBUG_LOCK_ALLOC", bound, 16, [], deps = ["PM_SLEEP"])
        OptionList.Op(self, "LOCK_STAT", bound, 8, [], deps = ["DEBUG_LOCK_ALLOC"])
        for bound in extra_spinlocks:
            OptionList.Op(self, "GENERIC_LOCKBREAK", bound, 4, [], deps = ["PM_RUNTIME"])
            OptionList.Op(self, "DEBUG_SPINLOCK", bound, 16, [], deps = ["PM_RUNTIME"])
            OptionList.Op(self, "SMP", bound, 4, [], deps = ["PM_RUNTIME"])
            OptionList.Op(self, "DEBUG_LOCK_ALLOC", bound, 16, [], deps = ["PM_RUNTIME"])
            OptionList.Op(self, "LOCK_STAT", bound, 8, [], deps = ["DEBUG_LOCK_ALLOC"])
        OptionList.Op(self, "DEBUG_LOCK_ALLOC", ["mutex.magic", "bus"], 16, [])
        OptionList.Op(self, "LOCK_STAT", ["mutex.magic", "bus"], 8, [], deps = ["DEBUG_LOCK_ALLOC"])

        lockdeps_LOCKDEP = [
            ["power.suspend_timer", "power.timer_expires"],
            ["power.work", "power.wait_queue"]
        ]
        
        # add lockdep_map ops
        for rg in lockdeps_LOCKDEP:
            OptionList.Op(self, "LOCKDEP", rg, 16, [], deps = ["PM_RUNTIME"])
            OptionList.Op(self, "LOCK_STAT", rg, 8, [], deps = ["LOCKDEP"])
        # finished adding options

        #print(self.oplist.ops)
