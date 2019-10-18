
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
        if cls not in Diff.diff_list:
            Diff.diff_list[cls] = []
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
        ret = "\n{}={}:{},{}".format(self.diff,self.expected, self.bounds, self.oplist)
        if self.fake:
            ret += " fake"
        return ret

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

