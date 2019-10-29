import r2pipe

from utils import *
from Structs import StructBase, spinlock_t, listhead_t
from OptionList import OptionList

class StructFile(StructBase):
    Members = [
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
            "raw_lock",       # 4
            "break_lock",     # CONFIG_GENERIC_LOCKBREAK: 4
            "magic",          # CONFIG_DEBUG_SPINLOCK: 4
            "owner_cpu",      # CONFIG_DEBUG_SPINLOCK: 4
            "owner",          # CONFIG_DEBUG_SPINLOCK: 4
            "dep_map",        # CONFIG_DEBUG_LOCK_ALLOC: lockdep_map
            "__end_rwlock__"
            ]
    SubMembers["f_ep_links"] = listhead_t.copy()
    SubMembers["f_tfile_llink"] = listhead_t.copy()
    SubMembers["f_ra"]=[
            "start",            # 4
            "size",             # 4
            "async_size",       # 4
            "ra_pages",         # 4
            "mmap_miss",        # 4
            "prev_pos",         # 8, loff_t
            "__end_ra__"
            ]

    PaddingList={
            # Empty
            }

    def __init__(self,name,oplist):
        super().__init__(name,oplist)
        self.populate_oplist()

    def populate_oplist(self):
        OptionList.Op.FullOp(self, "SMP", ["f_op","f_count"], 4, ["f_sb_list_cpu"])
        OptionList.Op.FullOp(self, "SECURITY", ["f_version","private_data"], 4, ["f_security"])
        OptionList.Op.FullOp(self, "EPOLL", ["private_data","f_mapping"], 16, ["f_ep_links", "f_file_llink"])
        OptionList.Op.FullOp(self, "DEBUG_WRITECOUNT", ["f_mapping","__end__"], 4, ["f_mnt_write_state"])
        # padding compensation, better less than more
        OptionList.Op.FullOp(self, "DEBUG_SPINLOCK", ["f_owner.lock","f_owner.lock.__end_rwlock__"], 12, ["f_owner.lock.magic", "f_owner.lock.owner_cpu","f_owner.lock.owner"])
        OptionList.Op.FullOp(self, "DEBUG_SPINLOCK", ["f_op","f_count"], 16, ["f_lock.rlock.raw_lock", "f_lock.rlock.magic", "f_lock.rlock.owner_cpu","f_lock.rlock.owner"])
        OptionList.Op.FullOp(self, "SMP", ["f_op","f_count"], 4, ["f_lock.rlock.raw_lock"], tradable = ["DEBUG_SPINLOCK"])

        # spinlock_t complications
        # lockdep_map: 8+4*(2)  CONFIG_LOCK_STAT:+8
        # appearance: DEBUG_LOCK_ALLOC: spinlock_t 
        OptionList.Op.FullOp(self, "GENERIC_LOCKBREAK", ["f_owner.lock","f_owner.lock.__end_rwlock__"], 4, ["f_onwer.lock.break_lock"])
        OptionList.Op.FullOp(self, "GENERIC_LOCKBREAK", ["f_op","f_count"], 4, ["f_lock.rlock.break_lock"])
        OptionList.Op.FullOp(self, "DEBUG_LOCK_ALLOC", ["f_owner.lock","f_owner.lock.__end_rwlock__"], 16, [])
        OptionList.Op.FullOp(self, "DEBUG_LOCK_ALLOC", ["f_op","f_count"], 16, [])
        OptionList.Op.FullOp(self, "LOCK_STAT", ["f_owner.lock","f_owner.lock.__end_rwlock__"], 8, [], deps=["DEBUG_LOCK_ALLOC"])
        OptionList.Op.FullOp(self, "LOCK_STAT", ["f_op","f_count"], 8, [], deps=["DEBUG_LOCK_ALLOC"])

#========================================================


def get_search_range_dentry_open(r2, r2_id, funclist):
    return get_search_range(r2,r2_id,funclist)

def get_search_range_file_sb_list_add(r2, r2_id, funclist):
    return get_search_range(r2,r2_id,funclist)
    
def process_file_sb_list_add(r2, r2_id, struct):
    print("processing file_sb_list_add...")
    ls = ['f_u.fu_list']
    tarfunc = "sym.file_sb_list_add"
    funclist = FuncRange(tarfunc,None)
    anal_tar_func(r2,r2_id,funclist)
    rg = get_search_range_file_sb_list_add(r2,r2_id,funclist)
    if rg[0]==-1:
        # function not present
        return True
    
    ret = []
    return struct.map_list(ret,ls)


def process_dentry_open(r2, r2_id, struct):
    print("processing __dentry_open...")
    ls = ['f_mode','f_mapping','f_path.dentry','f_path.mnt','f_flags','f_ra','f_op','f_pos']
    tarfunc = "sym.__dentry_open.isra"
    tarfunc = r2.cmd("fs symbols;f~{}".format(tarfunc)).strip().split(' ')[2]
    funclist = FuncRange(tarfunc,None)
    anal_tar_func(r2,r2_id,funclist)
    rg = get_search_range_dentry_open(r2,r2_id,funclist)
    if rg[0]==-1:
        # function not present
        return True

    iters = esil_exec_all_branch(r2,rg,rg[0])
    ret = iters("r2")
    while ret[0]==False:
        ret = iters("r2")
    ret = ret[1]
    ret.sort()
    if len(ret)-len(ls)==1:
        ls+=['f_mnt_write_state']
        struct.oplist.set_option('CONFIG_DEBUG_WRITECOUNT')
    return struct.map_list(ret,ls)

Struct_vanilla = None
Struct_msm = None

def init_struct_file(Msm_oplist, Van_oplist):
    global Struct_vanilla
    global Struct_msm
    Struct_vanilla = StructFile("vanilla", Van_oplist)
    Struct_msm = StructFile("msm", Msm_oplist)

def process_StructFile(Msm_r2, Van_r2):
    def run_comp(func):
        msm_res = func(Msm_r2, "msm", Struct_msm)
        van_res = func(Van_r2, "vanilla",Struct_vanilla)
        print("=================================================")
        if msm_res == False or van_res == False:
            print("Offset processing failed. Exiting...")
            exit()
    #run_comp(process_file_sb_list_add)
    run_comp(process_dentry_open)

    # the actual comparing
    Struct_msm.cmp(Struct_vanilla)

    print("Struct File analysis done!")
    print("=================================================")
