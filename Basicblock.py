import json
# basic block
# marked by start address
# for sorted block: always get its jump address first
class Basicblock:
    bb_list = {}
    choices = []
    stack = []
    next_choices = []
    last_block = None
    sort_last = False

    Loopend = -1
    Jump = -2
    Exhausted = -3

#    class Out:
#        def __init__(self,block_id):
#            block = Basicblock.bb_list[block_id]
#            self.block = block
#            self.hist_visited = False
#            self.count = 1

    def __str__(self):
        return hex(self.start)

    def __init__(self, item): #, addrs):
        self.json_src = item

        self.start = item['addr']
        self.end = item['addr']+item['size']-4 # need to remove the last one  
        self.endblock = False
        #self.subs = [x for x in addrs.keys() if x>=self.start and x<=self.end]
        Basicblock.bb_list[self.start] = self
        
        self.outs = []
        self.sorted = False
        if self.endblock:
            self.sorted = True
        self.parent_list = []
        self.visited = False

    def get_all_ends():
        ret = []
        for bb in Basicblock.bb_list.values():
            if bb.endblock:
                ret.append(bb.end)
        return ret

    def traversed():
        #flag=False
        for item in Basicblock.bb_list.values():
            if item.sorted == False:
                return False
        #    if item.sorted == True:
        #        flag = True
        #        break
        #if not flag:
        #    return False
        if len(Basicblock.stack)>0:
            return False
        return True

    def print_info(self):
        print("DEBUG: blockinfo")
        print("start: 0x{:x}".format(self.start))
        print("end: 0x{:x}".format(self.end))
        print("endblock:{}".format(self.endblock))
        s = [x.__str__() for x in self.outs]
        print("branches:{}".format(s))
        s = [x.__str__() for x in self.parent_list]
        print("incomes:{}".format(s))
        print("sorted:{}".format(self.sorted))
        print("DEBUG END")
    
    def add_outs(self):
        if 'jump' not in self.json_src: # is an end block
            self.endblock = True
        else:
            newout = Basicblock.bb_list[ self.json_src['jump'] ]
            #newout = Out( Basicblock.bb_list[ self.json_src['jump'] ])
            self.outs.append(newout)
            if 'fail' in self.json_src:
                newout = Basicblock.bb_list[ self.json_src['fail'] ]
                #newout = Out( Basicblock.bb_list[ self.json_src['fail'] ] )
                self.outs.append(newout)
        if len(self.outs)<2:
            self.sorted = True
        for out in self.outs:
            out.parent_list.append(self)
    
    def generate_map():
        for item in Basicblock.bb_list.values():
            item.add_outs()

    def init():
        Basicblock.sort_last = False
        if len(Basicblock.stack)>0:
            Basicblock.choices = Basicblock.stack.pop()
            Basicblock.next_choices = Basicblock.choices.copy()
        else:
            Basicblock.choices = []
            Basicblock.next_choices = []
        for item in Basicblock.bb_list.values():
            item.visited = False

    def sort(self, block):
        if self.sorted == True:
            return
        branch_conds = []
        branch_conds.append(block)
        other = [x for x in self.outs if x.start!=block.start]
        other = other[0]
        branch_conds.append(other)
        self.outs = branch_conds
        self.sorted = True
        self.visited = True

    def push_other(choice):
        next_choices = Basicblock.next_choices.copy()
        next_choices.append(1-choice)
        Basicblock.stack.append(next_choices)
        Basicblock.next_choices.append(choice)
    
    def get_next_choice(self):
        # not going into loops.
        # TODO: Deal with loops laters
        if Basicblock.traversed():
            return Basicblock.Exhausted

        if self.visited:
            return Basicblock.Loopend
        self.visited = True
        if Basicblock.sort_last:
            Basicblock.last_block.sort(self)
        Basicblock.sort_last = False
        Basicblock.last_block = self
        
        # endblock
        if self.endblock:
            return Basicblock.Loopend
        # no choices
        if len(self.outs)==1:
            return Basicblock.Jump
        # two branches
        ## still existing members in choices
        if len(Basicblock.choices)>0: 
            val = Basicblock.choices.pop(0)
            return val
        ## not end block, not fall through block, not in the choices: a normal block with two outs
        ### if not sorted in previous run, which means it's not visited either
        if not self.sorted:
            Basicblock.sort_last = True
        Basicblock.push_other(0)
        return 0

    def get_block(addr):
        if addr in Basicblock.bb_list.keys():
            return Basicblock.bb_list[addr]
        t = max([x for x in Basicblock.bb_list.keys() if x <= addr])
        return Basicblock.bb_list[t]

    def print_stack():
        print("=============stack=============")
        print("Blocks:")
        print(Basicblock.bb_list.keys())
        print("Stack:")
        for item in Basicblock.stack:
            print(item)
    
    def print_map():
        print("=============map=============")
        for item in Basicblock.bb_list.values():
            s = [x.__str__()  for x in item.outs]
            print("{}:{}".format(item,s))
