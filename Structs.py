#########################################
## Members[0: parent, 1: type, ...]
## offsets[0: off_parent, 1: off_type, ...]
## revmap{parent: 0, type: 1, ....}
########################################

from OptionList import OptionList
from Diff import Diff

#     Struct Device         Struct File
#               |            |
#               v            v
            ##################### 
            #     OptionList    # 
            # ################# # 
            # #     ########### # 
            # #     # Effect ## # 
            # #     ########### # 
            # # Op  # Effect ## # 
            # #     ########### # 
            # #     # Effect ## # 
            # #     ########### # 
            # ################# # 
            # #     ########### # 
            # #     # Effect ## # 
            # #     ########### # 
            # # Op  # Effect ## # 
            # #     ########### # 
            # #     # Effect ## # 
            # #     ########### # 
            # ################# # 
            ##################### 

UNDEF = -1
ERROR = -2

# Debug options for quick testing. Not used outside this file
DebugMembersPrt = False

# some shared contents
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

class StructBase:
    initialized = False
    Revmap = {}
    Members = []
    SubMembers = {}

    # TODO: some members may not present. needs to purge them if not presented
    PaddingList = {}

    @classmethod
    def range_in_range(cls,a,b):
        ar = [cls.getIndex(a[0]), cls.getIndex(a[1])]
        br = [cls.getIndex(b[0]), cls.getIndex(b[1])]
        if ERROR in ar or ERROR in br:
            exit()
        if ar[0]>=br[0] and ar[1]<=br[1]:
            return True
        else:
            return False

    def __init__(self,name,oplist):
        self.name = name
        if not type(self).initialized:
            type(self).init_members()
        self.offsets = [UNDEF]*len(type(self).Members) # offsets of each member
        self.offsets[0] = 0 # parent is always the first member
        if oplist.name != name:
            print("Error:wrong oplist given for {}, {}.".format(name,type(self).__name__))
            exit()
        self.oplist = oplist
        
    @classmethod
    def init_members(cls):
        print("initializing member list...")
        while len(cls.SubMembers.keys())>0:
            for item in cls.SubMembers.keys():
                if item not in cls.Members:
                    continue
                for sub in cls.SubMembers[item]:
                    sub = item+'.'+sub
                    cls.Members.insert(cls.Members.index(item), sub)
                cls.Members.remove(item)
                first = item+'.'+cls.SubMembers[item][0]
                cls.Members.insert(cls.Members.index(first), item)
                cls.SubMembers[item] = None
            cls.SubMembers = {x:y for x,y in cls.SubMembers.items() if y!=None}
        cls.initialized = True
        print("initializing Revmap...")
        for idx, item in enumerate(cls.Members):
            cls.Revmap[item] = idx
        print("initialization done.")
        if DebugMembersPrt:
            print(cls.Members)


    @classmethod
    def getIndex(cls,member):
        try:
            return cls.Revmap[member]
        except KeyError:
            print("KeyError: Member {} not exist in struct.".format(member))
            import traceback
            traceback.print_stack()
            return ERROR

    def __getOffsetById(self,i):
        if i < 0:
            return i
        try:
            return self.offsets[i]
        except IndexError:
            print("{} IndexError: Try accessing member {} but the total number is {}.".format(self.name,i,len(type(self).Members)-1))
            return ERROR

    def __getOffsetByName(self,name):
        return self.__getOffsetById(type(self).getIndex(name))

    def __setOffsetById(self,i,off):
        if i < 0:
            return False
        try:
            if self.offsets[i] != UNDEF and self.offsets[i] != off:
                print("{} Error: A confliction! {} offset is {} but trying to assign a different value {}.".format(
                    self.name,type(self).Members[i],self.getOffset(i),off))
                return False
            else:
                self.offsets[i] = off
                # the first offset of a submember is identical to the member itself
                # may not be vice versa, when it's not clear which member exactly was involved
                if "." in type(self).Members[i]:
                    prefix = type(self).Members[i].split('.')[0]
                    if type(self).Members[i-1] == prefix:
                        self.offsets[i-1] = off
                return True
        except:
            print("{} IndexError: Try accessing member {} but the total number is {}.".format(self.name,i,len(type(self).Members)-1))
            return False

    def __setOffsetByName(self,name, off):
        return self.__setOffsetById(type(self).getIndex(name), off)

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
        lastmem = "__beginning__"
        for idx, item in enumerate(type(self).Members):
            a = self.getOffset(idx)
            b = another.getOffset(idx)

            # deal with padding difference
            if item in type(self).PaddingList.keys():
                pad_flag = False
                if type(self).PaddingList[item] == None:
                    pad_flag = True
                else:
                    opname = type(self).PaddingList[item]
                    op_0 = self.oplist.get_option(opname)
                    op_1 = another.oplist.get_option(opname)
                    bool_0 = op_0.verified and op_0.set
                    bool_1 = op_1.verified and op_1.set
                    if bool_0 or bool_1:
                        pad_flag = True

                if pad_flag:
                    newdiff = diff
                    olddiff = diff
                    if diff!=0:
                        if diff > 0:
                            newdiff = diff//8*8
                        elif diff < 0:
                            newdiff = diff//(-8)*(-8)
                        diff = newdiff
                    print("Smooth out padding at {}, old diff: {}, new diff: {}.".format(item,olddiff,newdiff))
                else:
                    print("Neither side has member {}, skipping padding".format(item))

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
            # Logic: the difference will remain constant if no new diff is introduced, save for padding issues which can be resolved.
            new_diff = a-b
            if diff!=new_diff:
                diff, true_diff = new_diff, new_diff-diff
                if true_diff<0:
                    missing = self.name
                else:
                    missing = another.name
                last_idx = idx-1
                while last_idx>=0 and (self.offsets[last_idx]==UNDEF or another.offsets[last_idx]==UNDEF):
                    last_idx = last_idx-1
                print("possible missing members in {} kernel, between {} and {}, offsets: {}, {}, diff: {}".format(
                    missing, type(self).Members[last_idx], type(self).Members[idx],hex(a),hex(b),true_diff))
                lastmem = item
                Diff(type(self),true_diff,tuple((type(self).Members[last_idx], type(self).Members[idx])),oplist = self.oplist)
            else:
                #print("member registered in both kernel: {}, offset {}, {}.".format(type(self).Members[idx],hex(a), hex(b)))
                None
        return self.oplist.analyze_between(another,type(self))

    def map_list(self,offs, mems):
        if len(offs) != len(mems):
            print("Error: list size mismatch between struct members ({}) and returned members ({})".format(len(mems),len(offs)))
            return False
        mems.sort(key=lambda x: type(self).getIndex(x))
        offs.sort()
        print("Found matches: {}, mapping to {}".format([hex(x) for x in offs],mems))
        for idx, mem in enumerate(mems):
            off = offs[idx]
            if not self.setOffset(mem, off):
                return False
        return True
