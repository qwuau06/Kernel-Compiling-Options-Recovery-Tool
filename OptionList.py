import itertools
from AnswerList import AnswerList
from Diff import Diff

DebugAllPermsSep = False
DebugAllPerms = False

def powerset(iterable):
    s = list(iterable)
    return itertools.chain.from_iterable(itertools.combinations(s, r) for r in range(len(s)+1))

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

