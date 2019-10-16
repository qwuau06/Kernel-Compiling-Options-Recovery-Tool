#########################################
## Members[0: parent, 1: type, ...]
## offsets[0: off_parent, 1: off_type, ...]
## revmap{parent: 0, type: 1, ....}
########################################

import itertools
from AnswerList import AnswerList

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
DebugAllPermsSep = False
DebugAllPerms = False
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

def powerset(iterable):
    s = list(iterable)
    return itertools.chain.from_iterable(itertools.combinations(s, r) for r in range(len(s)+1))

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


# detection logic:
#   first round: go through all the members. some members are option locked, thus can determine a list of ops
#   second round: for each diff = msm.member_off -  linux.member_off
class OptionList:
    # class of a single option
    class Op:
        Cfg = "CONFIG_"
        Verbose = True
        class Effect:
            def __init__(self, struct, opname, extrabytes, extramems, deps, antimems,tradable):
                self.cls = type(struct)
                self.opname = opname
                self.bytes = extrabytes
                self.mems = extramems
                self.deps = deps # only the most direct dep. chains of deps aren't recorded, all deps in parallel
                self.antimems = antimems
                self.children = []
                self.tradable = tradable

            def __repr__(self):
                ret = "Info:\n"
                ret+= "  class:{}\n".format(self.cls.__name__)
                ret+= "  bytes:{}\n".format(self.bytes)
                ret+= "  mems:{}\n".format(self.mems)
                ret+= "  deps:{}\n".format(self.deps)
                ret+= "  antimems:{}\n".format(self.antimems)
                children = [x.name for x in self.children]
                ret+= "  children:{}\n".format(children)
                ret+= "  tradable:{}\n".format(self.tradable)
                return ret

        # each option isn't bound to a specific struct, but each effect is, and __init__ is called per effect
        def __init__(self, name):
            self.name = name
            # {[bound]:{extramems, extrabytes, subs}}
            self._effects = {}

            self.set = False
            self.verified = False
            self.suspected = False

        def get_key_names(self):
            return dict.fromkeys([x[0] for x in self._effects.keys()]).keys()

        @classmethod
        def get_op(cls, oplist, name):
            if name != "(archdata.dma_ops)":
                name = OptionList.Op.Cfg+name
            #print("{}:{}".format(oplist.name,name))
            existed = [x for x in oplist.ops if x.name == name]
            if len(existed)>0:
                return existed[0]
            elif len(existed)>1:
                print("Error: duplicate option {}.".format(name))
                exit()
            else:
                newop = OptionList.Op(name)
                oplist.ops.append(newop)
                return newop
        
        @classmethod
        def DirectOp(cls, oplist, name):
            newop = cls.get_op(oplist,name)
            return newop

        @classmethod
        def FullOp(cls, struct, name, bound, extrab, extram, deps=[], antimems = [],tradable = []):
            oplist = struct.oplist
            newop = cls.get_op(oplist,name)
            deps = [OptionList.Op.Cfg+x for x in deps]
            tradable = [OptionList.Op.Cfg+x for x in tradable]
            for item in deps:
                pars = [x for x in oplist.ops if x.name==item]
                if len(pars)==0:
                    print("Error: {} doesn't exist in the list yet.".format(item))
                    exit()
                elif len(pars)>1:
                    print("Error: {} has more than one copy in the list.".format(item))
                    exit()
                par = pars[0]
                # insert children
                par_effs = par.get_eff_list(type(struct))
                self_effs = newop.get_eff_list(type(struct))
                for pareffbd in par_effs.keys():
                    for bd in self_effs.keys():
                        if type(struct).range_in_range(bd,pareffbd):
                            if newop not in par_effs[pareffbd].children:
                                par_effs[pareffbd].children.append(newop)
                            break
            # add new effect into dict
            newop._effects[tuple((type(struct).__name__,tuple((bound))))] = OptionList.Op.Effect(name, struct, extrab, extram, deps, antimems,tradable)
            return newop

        def __repr__(self):
            ret = "\n\n{}:\n".format(self.name)
            if OptionList.Op.Verbose:
                for rg,eff in self._effects.items():
                    ret+=" {}:".format(rg)
                    ret+=eff.__repr__()
            else:
                for rg,eff in self._effects.items():
                    ret+=" \n{}: {}+extra:{}".format(rg, eff.bytes, [x.name for x in eff.children])
            return ret

        def get_eff_list_name(self,clsname):
            return {t[1]:self._effects[t] for t in self._effects.keys() if t[0]==clsname}

        def get_eff_list(self,cls):
            return {t[1]:self._effects[t] for t in self._effects.keys() if t[0]==cls.__name__}

        # get corresponding effect to a bound
        def get_eff(self,bounds, cls):
            for effbd,eff in self.get_eff_list(cls).items():
                if cls.range_in_range(effbd, bounds):
                    return eff
            print("Error: Didn't find {} with in {}.".format(bounds, self.name))
            return None

    def __init__(self,name, anls):
        self.name = name
        self.ops = []
        self.anls = anls
        # populate is left for each struct. but there are some always exist options
        OptionList.Op.DirectOp(self, "TRACING")
        

    def set_option(self, opname, val=True, suspected = False, force=False):
        if opname not in [o.name for o in self.ops]:
            print ("Error: non-existing option {}!".format(opname))
            exit()
        op = self.get_option(opname)
        if op.verified==True and op.set != val:
            if not force:
                print("Error: conflicting options: {}".format(opname))
                import traceback
                traceback.print_stack()
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

    def check_option(self,opname):
        op = self.get_option(opname)
        if op.set and op.verified and not op.suspected:
            return True
        return False

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

    def analyze_between(self, another, cls):
        anls = self.anls
        another = another.oplist
        Diff.pos_oplist = self
        Diff.neg_oplist = another

        print("=================================================")
        print("Diff list: {}".format(len(Diff.get_diff_list(cls))))

        Diff.update_diffs(cls)

        #dry_list = self.ops
        a_list = self.ops
        b_list = another.ops
        print("Start analysis...")

        def must_op_str(x,who): anls.oplist[who.name][x.name] = True
        def none_op_str(x,who): anls.oplist[who.name][x.name] = False
        def unkn_op_str(x): anls.unknown[tuple(x.bounds)] = x.diff


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
        Diff.update_diffs(cls)
        print("Known members in {:7s}:{}".format(self.name,[x.name for x in a_list if x.verified and x.set and not x.suspected])) # sure existing members
        print("Known members in {:7s}:{}".format(another.name,[x.name for x in b_list if x.verified and x.set and not x.suspected])) # sure existing members

        # Round 2: if diff is larger than a specific value, then a config is confirmed
        # TODO
        None

        # Round 3: no options. If there's a difference then it is an unknown tag
        for diff in Diff.get_diff_list(cls):
            if len(diff.oplist)==0: # no options
                unkn_op_str(diff)
        # Round 4: only has one option and size matches:
            elif len(diff.oplist)==1:   # one option
                opname = diff.oplist[0]
                op_a = self.get_option(opname)
                op_b = another.get_option(opname)
                # TODO: currently we assume op_a == op_b so we let op = op_a
                if diff.get_bytes(op_a) == abs(diff.diff):
                    if diff.diff >0:
                        op = op_a
                        st = self
                    else:
                        op = op_b
                        st = another
                    must_op_str(op,st)
                    #diff.expected += op.get_bytes()
                    #op.verified = True
                    #op.set = True
                    st.set_option(op.name)
                    print("{} confirmed by round 4.".format(op.name))
                    eff = diff.get_eff(op_a)
                    if len(eff.deps)==1:
                        op = eff.deps[0]
                        #op.verified = True
                        #op.set = True
                        st.set_option(op.name)
                        print("{} confirmed by round 4.".format(op.name))
                else:
                    unkn_op_str(diff)
        # Round 5: more than 2 options but only one option is below diff
            else:
                # TODO: remove self ref, and the implication of same options
                # print(diff.oplist)
                opnames = [op for op in diff.oplist if diff.get_bytes(self.get_option(op))>0 and diff.get_bytes(self.get_option(op))<=abs(diff.diff)]
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
                    #op.verified = True
                    #op.set = True
                    st.set_option(op.name)
        Diff.update_diffs(cls)

    def calc_options(self, another):
        if self.name != "msm":
            print("Error:calc_option can only be called by msm kernel.")
            exit()
        anls = self.anls
        a_list = self.ops
        b_list = another.ops
        ret = []

        # func factory for case specific options
        def case_fac():
            case = AnswerList.Case(anls)
            def unkn_op_str(x): case.unknown[tuple(x.bound)] = x.diff
            def poss_op_str(x,who): case.oplist[who].append(x)
            def add_details(d): case.details = d
            def set_diff(d): case.diff = d
            def set_diff_str(d): case.diff_str = d 
            return unkn_op_str, poss_op_str, add_details, set_diff, set_diff_str
        # Eradicated enough cases, now need to run a powerset
        # diff_list = [x for x in diff_list if x.expected != x.diff]
        a_dep_list = [x for x in a_list if x.verified and x.set and not x.suspected] # sure existing members
        b_dep_list = [x for x in b_list if x.verified and x.set and not x.suspected] # sure existing members

        a_list = []
        b_list = []
        print("Populating perm lists")
        for diff in Diff.get_merged_list():
            for opname in diff.oplist:
                a_op = self.get_option(opname)
                b_op = another.get_option(opname)
                if a_op not in a_list and not(a_op.verified and not a_op.set) and a_op not in a_dep_list:
                    a_list.append(a_op)
                if b_op not in b_list and not(b_op.verified and not b_op.set) and b_op not in b_dep_list:
                    b_list.append(b_op)
        for cls in Diff.diff_list.keys():
            print(Diff.get_diff_list(cls))
                
        print("first round eradication done.")
        print("dep list {:7s}:{}".format( self.name, [x.name for x in a_dep_list] ))
        print("dry list {:7s}:{}".format( self.name, [x.name for x in a_list] ))
        print("dep list {:7s}:{}".format( another.name, [x.name for x in b_dep_list] ))
        print("dry list {:7s}:{}".format( another.name, [x.name for x in b_list] ))

        # making the powerset
        a_perms = list(powerset(a_list))
        b_perms = list(powerset(b_list))
        perms = []

        def filter_perms(perms, x_deps, oplist, cls):
            ret = []
            for perm in perms:
                flag = True
                # for each member, if it has dependencies and none of dependencies show up in the case, move it to garbage cases
                for op in perm:
                    for eff in op.get_eff_list(cls).values():
                        if len(eff.deps) == 0:
                            break 
                        par_flag = False
                        for par in eff.deps:
                            if oplist.get_option(par) in x_deps:
                                par_flag = True
                                break
                            if oplist.get_option(par) in perm:
                                par_flag = True
                                break
                        if not par_flag:
                            flag = False
                            break
                if flag:
                    ret.append(perm)
            return ret

        for cls in Diff.diff_list.keys():
            a_perms = filter_perms(a_perms, a_dep_list, Diff.pos_oplist,cls)
            b_perms = filter_perms(b_perms, b_dep_list, Diff.neg_oplist,cls)
        
        if DebugAllPermsSep:
            print("{} perms:".format(self.name))
            for y in a_perms:
                print([x.name for x in y])
            print("{} perms:".format(another.name))
            for y in b_perms:
                print([x.name for x in y])

        for a in a_perms:
            for b in b_perms:
                list1 = [x.name for x in a]
                list2 = [x.name for x in b]
                samelist = list(set(list1).intersection(list2))
                discard=False
                if len(samelist)>0:
                    concat_list = [*a,*b]
                    concat_list = [op for op in concat_list if op.name not in samelist]
                    discard=True
                    for poss_dep in samelist:
                        for op in concat_list:
                            for clsname in op.get_key_names():
                                if len( [eff for eff in op.get_eff_list_name(clsname).values() if poss_dep in eff.deps] )==0:
                                    discard=False
                                    break
                        if not discard:
                            break
                if not discard:
                    perms.append({'a':a, 'b':b})
        print("all permutations: {}.".format(len(perms)))

        if DebugAllPerms:
            for item in perms:
                al = [a.name for a in item['a']]
                bl = [b.name for b in item['b']]
                print("{{{},{}}}".format(al,bl))

        # core code for config powerset
        res_out = {}
        for perm in perms:
            flattened_perm = tuple(( [*[self.name+"."+op.name for op in perm['a']],*[another.name+"."+op.name for op in perm['b']]  ]   ))
            for op in [*perm['a'],*perm['b']]:
                op.suspected = True
                op.verified = True
                op.set = True
            Diff.update_diffs_all(fake=True)
            if Diff.valid_list(cls):
                details = ("Post update:...\n{}".format(Diff.diff_list))
                # add into dict
                total_diff = 0 
                diff_str = "debug: "
                for x_diff in Diff.get_merged_list():
                    total_diff += abs(x_diff.diff-x_diff.expected)
                    diff_str += "{}-{}, ".format(x_diff.diff,x_diff.expected)
                res_out[flattened_perm] = tuple((total_diff,details,diff_str))
            # clean up, diff_list will be auto cleaned by next round
            for op in [*perm['a'],*perm['b']]:
                op.suspected = False
                op.verified = False
                op.set = False

        case = 0
        Diff.get_diff_list(cls).append(self)
        for perm, res in sorted(res_out.items(),key=lambda kv:kv[1][0] ):
            if res[0] > AnswerList.Threshold:
                continue
            if case >= AnswerList.Maxcount:
                break
            unkn_op_str, poss_op_str, add_details, set_diff, set_diff_str = case_fac()
            if res[0] != 0 :
                set_diff(res[0])
                set_diff_str(res[2])
            for op in perm:
                names = op.split('.')
                poss_op_str(names[1],names[0])
            add_details(res[1])
            case += 1

        anls.prt()
        return ret

# Diff between two list of offsets, and corresponding options
# Notice that it isn't tied to any specific struct; it's independent
class Diff:
    diff_list = {}
    pos_oplist = None
    neg_oplist  = None
    
    def __init__(self, cls, diff, bounds, oplist=None, fake=False):
        self.cls = cls
        self.diff = diff        # diff
        self.bounds = bounds    # (lower, upper)
        self.oplist = [] # notice it only register the names
        self.expected = 0
        self.get_eff = lambda o: o.get_eff(self.bounds,cls)
        self.get_bytes = lambda o: o.get_eff(self.bounds,self.cls).bytes if o.get_eff(self.bounds,self.cls)!=None else -1
        self.fake = fake
        if self.cls not in Diff.diff_list:
            Diff.diff_list[self.cls] = []
        Diff.get_diff_list(self.cls).append(self)
        if oplist:
            for op in oplist.ops:
                if self.option_in_range(op,self.cls):
                    self.oplist.append(op.name)
        if not self.fake:
            print("New Diff creating: diff:{}, bounds:{}, fake={}".format(self.diff,self.bounds,self.fake))
            
    def get_diff_list(cls):
        return Diff.diff_list[cls]

    def get_merged_list():
        return [x for y in Diff.diff_list.values() for x in y]

    def valid_list(cls):
        for diff in Diff.get_diff_list(cls):
            if not diff.fake and abs(diff.expected) > abs(diff.diff):
                return False
        return True

    def option_in_range(self, option, cls):
        opbound = option.get_eff_list(cls).keys()
        for opbd in opbound: # self bound inside bd
            if cls.range_in_range(opbd,self.bounds):
                return True
        return False

    def __repr__(self):
        #opls = [y.name for y in self.oplist for x in OptionList.get_option(y).effects if len(x.deps)==0]
        #opls += ["child:"+y.name for y in self.oplist for x in OptionList.get_option(y).effects if len(x.deps)>0]
        return "\n{}={}:{},{}".format(self.diff,self.expected, self.bounds, self.oplist)

    def update_diffs_all(*,fake=False,debug=False):
        for cls in Diff.diff_list.keys():
            Diff.update_diffs(cls,fake=fake,debug=debug)

    # update diffs after changes in options.
    # TODO:this function should not depend on struct, but currently doesn't have a better way, unless rewriting it.
    def update_diffs(cls,*,fake=False,debug=False):
        if Diff.pos_oplist == None or Diff.neg_oplist == None:
            print("please set positive and negetive structs first")
            exit()
        pos_op = Diff.pos_oplist
        neg_op = Diff.neg_oplist

        def dbgprint(*args, **kwargs):
            if debug:
                print(*args, **kwargs)

        Diff.diff_list[cls] = [df for df in Diff.get_diff_list(cls) if not df.fake]
        for diff in Diff.get_diff_list(cls):
            diff.expected = 0
        new_list = []
        delete_flag = True
        for op in pos_op.ops:
            if op.verified and op.set:
                for k,v in op.get_eff_list(cls).items():
                    get = lambda x: pos_op.get_option(x)
                    # if dep not satisfied
                    if len(v.deps)>0 and len([x for x in v.deps if get(x).verified and get(x).set])==0:
                        dbgprint("{} of {} has no effect due to unsatisfied dep.".format(k,op.name))
                        continue
                    # if tradable exists
                    if len(v.tradable)>0 and len([x for x in v.tradable if get(x).verified and get(x).set])>0:
                        dbgprint("{} of {} has no effect due to existing tradable.".format(k,op.name))
                        continue
                    dbgprint("{} of {} takes effect.".format(k,op.name))
                    new_list+= [tuple((k,v.bytes))]
                if op.suspected:
                    delete_flag = False
        for op in neg_op.ops:
            if op.verified and op.set:
                for k,v in op.get_eff_list(cls).items():
                    get = lambda x: neg_op.get_option(x)
                    # if dep not satisfied
                    if len(v.deps)>0 and  len([x for x in v.deps if get(x).verified and get(x).set])==0:
                        dbgprint("{} of {} has no effect due to unsatisfied dep.".format(k,op.name))
                        continue
                    # if tradable exists
                    if len(v.tradable)>0 and len([x for x in v.tradable if get(x).verified and get(x).set])>0:
                        dbgprint("{} of {} has no effect due to existing tradable.".format(k,op.name))
                        continue
                    dbgprint("{} of {} takes neg effect.".format(k,op.name))
                    new_list+= [tuple((k,-v.bytes))]
                if op.suspected:
                    delete_flag = False
        for item in new_list:
            bounds, extrabytes = item[0],item[1]
            flag = False
            for diff in Diff.get_diff_list(cls):
                #print("diff bound:{}, option bound:{}".format(diff.bounds, bounds))
                if cls.range_in_range(bounds, diff.bounds):
                    flag = True
                    diff.expected += extrabytes
                    dbgprint("After:{} gained {} bytes.".format(diff.bounds, extrabytes))
            if not flag:
                new_diff_flag = True
                for diff in Diff.get_diff_list(cls):
                    if cls.range_in_range(diff.bounds,bounds):
                        dbgprint("After:{} gained {} bytes.".format(diff.bounds, extrabytes))
                        new_diff_flag = False
                        diff.expected += extrabytes
                if new_diff_flag:
                    Diff(cls,-extrabytes, bounds, pos_op, fake=True)
                    dbgprint("New gap {} created with {}.".format(bounds,-extrabytes))
        Diff.diff_list[cls] = [x for x in Diff.get_diff_list(cls) if not (x.fake and x.diff == x.expected)]
#        if delete_flag:
#            Diff.get_diff_list(cls) = [x for x in Diff.get_diff_list(cls) if x.diff != x.expected]

    def saturated(cls):
        for diff in Diff.get_diff_list(cls):
            if diff.expected != diff.diff:
                return False
        return True

