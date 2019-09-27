import r2pipe

from utils import *
from Structs import StructBase, OptionList, spinlock_t, listhead_t

class StructFile(StructBase):
    StructMembers = [
            "f_u",              # EXPAND; 8
            "f_path",           # 8
            "f_op",             # 4
            "f_lock",           # spinlock_t
            "f_sb_list_cpu",    # CONFIG_SMP: 4
            "f_count",          # 4
            "f_flags",          # 4
            "f_mode",           # bitwise
            "f_pos",            # 8, loff_t
            "f_owner",          # EXPAND
            "f_cred",           # 4
            "f_ra",             # EXPAND
            "f_version",        # 8
            "f_security",       # CONFIG_SECURITY: 4
            "private_data",     # 4
            "f_ep_links",       # CONFIG_EPOLL: 8
            "f_tfile_llink",    # CONFIG_EPOLL: 8
            "f_mapping",        # 4
            "f_mnt_write_state",# CONFIG_DEBUG_WRITECOUNT: 4
            "__end__"
            ]

    SubMembers = {}
    SubMembers["f_u"]=[
            "fu_list",          # 8
            "fu_rcuhead"        # 8
            ]
    SubMembers["f_u.fu_list"] = listhead_t.copy()
    SubMembers["f_u.fu_rcuhead"]=[
            "next",             # 4
            "func",             # 4
            ]
    SubMembers["f_path"]=[
            "mnt",              # 4
            "dentry"            # 4
            ]
    SubMembers["f_lock"] = spinlock_t.copy()
    SubMembers["f_owner"]=[
            "lock",             # EXPAND; this is rw_lock not spinlock
            "pid",              # 4
            "pid_type",         # 4
            "uid",              # 4
            "euid",             # 4
            "signum",           # 4
            "__end_owner__"
            ]
    SubMembers["f_owner.lock"]=[
            "raw_lock",       # CONFIG_DEBUG_SPINLOCK || CONFIG_SMP: 4
            "break_lock",     # CONFIG_GENERIC_LOCKBREAK: 4
            "magic",          # CONFIG_DEBUG_SPINLOCK: 4
            "owner_cpu",      # CONFIG_DEBUG_SPINLOCK: 4
            "owner",          # CONFIG_DEBUG_SPINLOCK: 4
            "dep_map",        # CONFIG_DEBUG_LOCK_ALLOC: lockdep_map
            "__end_rwlock__"
            ]
    SubMembers["f_ep_links"] = lockhead_t.copy()
    SubMembers["f_tfile_llink"] = lockhead_t.copy()
    SubMembers["f_ra"]=[
            "start",            # 4
            "size",             # 4
            "async_size",       # 4
            "ra_pages",         # 4
            "mmap_miss",        # 4
            "prev_pos",         # 8, loff_t
            "__end_ra__"
            ]

    PaddingList=[
            # Empty
            ]

    def __init__(self,name):
        super().__init__(name)
        self.populate_oplist()

    def populate_oplist(self):
        OptionList.Op(self, "SMP", ["f_op","f_count"], 4, ["f_sb_list_cpu"])
        OptionList.Op(self, "SECURITY", ["f_version","private_data"], 4, ["f_security"])
        OptionList.Op(self, "EPOLL", ["private_data","f_mapping"], 16, ["f_ep_links", "f_file_llink"])
        OptionList.Op(self, "DEBUG_WRITECOUNT", ["f_mapping","__end__"], 4, ["f_mnt_write_state"])
        OptionList.Op(self, "DEBUG_SPINLOCK", ["f_owner.lock","f_owner.__end_rwlock__"], 16, ["f_owner.lock.raw_lock", "f_owner.lock.magic", "f_owner.lock.owner_cpu","f_owner.lock.owner"])
        OptionList.Op(self, "SMP", ["f_owner.lock","f_owner.__end_rwlock__"], 4, ["f_owner.lock.raw_lock"], tradable = ["DEBUG_SPINLOCK"])
        OptionList.Op(self, "DEBUG_SPINLOCK", ["f_op","f_count"], 16, ["f_lock.rlock.raw_lock", "f_lock.rlock.magic", "f_lock.rlock.owner_cpu","f_lock.rlock.owner"])
        OptionList.Op(self, "SMP", ["f_op","f_count"], 4, ["f_lock.rlock.raw_lock"], tradable = ["DEBUG_SPINLOCK"])

        # spinlock_t complications
        # lockdep_map: 8+4*(2)  CONFIG_LOCK_STAT:+8
        # appearance: DEBUG_LOCK_ALLOC: spinlock_t 
        OptionList.Op(self, "GENERIC_LOCKBREAK", ["f_owner.lock","f_owner.__end_rwlock__"], 4, ["f_onwer.lock.break_lock"])
        OptionList.Op(self, "GENERIC_LOCKBREAK", ["f_op","f_count"], 4, ["f_lock.rlock.break_lock"])
        OptionList.Op(self, "DEBUG_LOCK_ALLOC", ["f_owner.lock","f_owner.__end_rwlock__"], 16, [])
        OptionList.Op(self, "DEBUG_LOCK_ALLOC", ["f_op","f_count"], 16, [])
        OptionList.Op(self, "LOCK_STAT", ["f_owner.lock","f_owner.__end_rwlock__"], 8, [], deps=["DEBUG_LOCK_ALLOC"])
        OptionList.Op(self, "LOCK_STAT", ["f_op","f_count"], 8, [], deps=["DEBUG_LOCK_ALLOC"])

#========================================================

Struct_vanilla = StructFile("vanilla")
Struct_msm = StructFile("msm")

def process_dentry_open(r2, r2_id, struct):
    print("processing __dentry_open...")
    tarfunc = "sym.__dentry_open.isra"
    tarfunc = r2.cmd("fs symbols;f~{}".format(tarfunc)).strip().split(' ')[2]

    None

def process_StructFile():
    def run_comp(func):
        msm_res = func(Msm_r2, "msm", Struct_msm)
        van_res = func(Van_r2, "vanilla",Struct_vanilla)
        print("=================================================")
        if msm_res == False or van_res == False:
            print("Offset processing failed. Exiting...")
            exit()
    run_comp(process_dentry_open)

    # the actual comparing
    Struct_msm.cmp(Struct_vanilla)

    print("=================================================")
    print("Struct File analysis done!")
