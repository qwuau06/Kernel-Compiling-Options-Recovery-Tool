StructMembers = [
        "f_u",              # 8
        "f_path",           # 8
        "f_op",             # 4
        "f_lock",           # spinlock_t
        "f_sb_list_cpu",    # CONFIG_SMP: 4
        "f_count",          # 4
        "f_flags",          # 4
        "f_mode",           # bitwise
        "f_pos",            # 8
        "f_owner",          # EXPAND
        "f_cred",           # 4
        "f_ra",             # EXPAND
        "f_version",        # 8
        "f_security",       # CONFIG_SECURITY: 4
        "private_data",     # 4
        "f_ep_links",       # CONFIG_EPOLL: 8
        "f_tfile_llink",    # CONFIG_EPOLL: 8
        "f_mapping",        # 4
        "f_mnt_write_state" # CONFIG_DEBUG_WRITECOUNT: 4
        ]

SubMembers = {}
SubMembers["f_owner"]=[
        "lock",             # EXPAND
        "pid",              # 4
        "pid_type",         # 4
        "uid",              # 4
        "euid",             # 4
        "signum"            # 4
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
SubMembers[]

