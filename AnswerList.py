
# Used for final output.
class AnswerList:
    # unknown are expressed as tuple(bound):diff
    class Case:
        def __init__(self,ls):
            self.oplist = {ls.a_name:[], ls.b_name:[]}
            self.unknown = {}
            self.diff = 0
            self.diff_str = ""
            self.details = ""
            ls.caselist.append(self)

    Threshold = 24
    Maxcount = 3 
    Verbose = False
    Deprecated = False

    def __init__(self,a_name,b_name):
        self.caselist = []
        self.a_name = a_name
        self.b_name = b_name
        self.unknown = {}
        self.oplist = {self.a_name:{}, self.b_name:{}}

    def prt_case(self, case, count):
        print("\n========================================================================")
        print("Case {}:".format(count))
        print("Total diff: {}".format(case.diff))
        print("------------------------------------------------------------------------")
        print("               msm                 |               vanilla              ")
        print("------------------------------------------------------------------------")
        t_name = self.a_name
        g_name = self.b_name
        if self.a_name == "vanilla":
            t_name = self.b_name
            g_name = self.a_name
        msm_list = [idx for idx, x in self.oplist[t_name].items() if x]
        msm_list2= [idx for idx in case.oplist[t_name]]
        msm_list = [*msm_list, *msm_list2]
        van_list = [idx for idx, x in self.oplist[g_name].items() if x]
        van_list2= [idx for idx in case.oplist[g_name]]
        van_list = [*van_list, *van_list2]
        maxc = max( len(msm_list), len(van_list) )
        msm_list.sort()
        van_list.sort()
        for i in range(maxc):
            a,b = "",""
            if i< len(msm_list):
                a = msm_list[i].split("=")[0]
            if i< len(van_list):
                b = van_list[i].split("=")[0]
            print("{:35s}|{:35s}".format(a,b))
        if len(self.unknown.keys())>0 or len(case.unknown.keys())>0:
            print("------------------------------------------------------------------------")
            print("Unknown:")
            for bound,diff in self.unknown.items():
                print("{}:{}".format(bound,diff))
            for bound,diff in case.unknown.items():
                print("{}:{}".format(bound,diff))
        if(AnswerList.Verbose):
            print("------------------------------------------------------------------------")
            print("Details:")
            print(case.details)
        print("========================================================================\n")

    def prt(self):
        print("\nConfigs:")
        print("Maximum cases: {}".format(AnswerList.Maxcount))
        print("Maximum total offset difference: {}".format(AnswerList.Threshold))
        print("Printing results...")
        if AnswerList.Verbose:
            print("Verbose output on")
        print("Total cases: {}".format(len(self.caselist)))

        # this is deprecated and is not supposed to be used. Use prt_case instead (at the end of method)
        if AnswerList.Deprecated:
            must_op_str = lambda x,who:print("{}: {} True.".format(who,x))
            poss_op_str = lambda x,who:print("{}: {} Potentially True.".format(who,x))
            none_op_str = lambda x,who:print("{}: {} False.".format(who,x))
            unkn_op_str = lambda bound,diff:print("Unknown Option between {} and {}, size {}.".format(bounds[0],bounds[1],diff))
            for item,ans in self.oplist[self.a_name].items():
                if ans:
                    must_op_str(item,self.a_name)
                else:
                    none_op_str(item,self.a_name)
            for item,ans in self.oplist[self.b_name].items():
                if ans:
                    must_op_str(item,self.b_name)
                else:
                    none_op_str(item,self.b_name)
            for bound, diff in self.unknown.items():
                unkn_op_str(bound, diff)
            count = 0
            for item in self.caselist:
                if item.diff > AnswerList.Threshold:
                    continue
                if item.diff == 0:
                    print("\nCase {}: Exact Match:".format(count))
                else:
                    print("\nCase {}: Non-Exact Match with diff {}:".format(count,item.diff))
                for x in self.oplist[self.a_name].items():
                    if ans:
                        must_op_str(item,self.a_name)
                for x in item.oplist[self.a_name]:
                    poss_op_str(self.a_name,x)
                for x in self.oplist[self.b_name].items():
                    if ans:
                        must_op_str(item,self.b_name)
                for x in item.oplist[self.b_name]:
                    poss_op_str(self.b_name,x)
                for bound, diff in item.unknown.items():
                    unkn_op_str(bound, diff)
                if(AnswerList.Verbose):
                    print(item.details)
                    print(item.diff_str)
                count+=1
                if count >= AnswerList.Maxcount:
                    break
        else:
            count = 0
            for case in self.caselist:
                self.prt_case(case,count)
                count+=1
                if case.diff>AnswerList.Threshold:
                    break
                if count>=AnswerList.Maxcount:
                    break
