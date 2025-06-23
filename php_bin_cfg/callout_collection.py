import os
import pdb
from typing import Dict
from angrutils import output
from callout import CallOut, CallOutType
from func_collection import FuncCollection
from shared_object import ObjCollection

class CallOutResolver:
    def __init__(self) -> None:
        self.plt_callouts: Dict[str, Dict[str, CallOut]]= {} # shared object it belongs to, then index by its symbolic_name
        self.ind_callouts: Dict[int, CallOut] = {} # {call_site: callout}
    
    def collect_plt_callouts(self, fc: FuncCollection):
        # first collect on non api functions
        funcs = fc.funcs
        for php_fn in funcs.values():
            plt_callouts = list(php_fn.get_callouts(CallOutType.RESOLVED_PLT))
            for plt_call in plt_callouts:
                if plt_call.owner_obj_name not in self.plt_callouts:
                    self.plt_callouts[plt_call.owner_obj_name] = {}
                self.plt_callouts[plt_call.owner_obj_name][plt_call.symbolic_name] = plt_call
        # then collect on api functions
        funcs = fc.api_funcs
        for php_fn in funcs.values():
            plt_callouts = list(php_fn.get_callouts(CallOutType.RESOLVED_PLT))
            for plt_call in plt_callouts:
                if plt_call.owner_obj_name not in self.plt_callouts:
                    self.plt_callouts[plt_call.owner_obj_name] = {}
                self.plt_callouts[plt_call.owner_obj_name][plt_call.symbolic_name] = plt_call

    def collect_ind_callouts(self, fc: FuncCollection):
        funcs = fc.funcs
        for php_fn in funcs.values():
            ind_callouts = list(php_fn.get_callouts(CallOutType.INDIRECT_REG))
            ind_callouts.extend(list(php_fn.get_callouts(CallOutType.INDIRECT_MEM)))
            for ind_call in ind_callouts:
                self.ind_callouts[ind_call.call_site] = ind_call

        funcs = fc.api_funcs
        for php_fn in funcs.values():
            ind_callouts = list(php_fn.get_callouts(CallOutType.INDIRECT_REG))
            ind_callouts.extend(list(php_fn.get_callouts(CallOutType.INDIRECT_MEM)))
            for ind_call in ind_callouts:
                self.ind_callouts[ind_call.call_site] = ind_call

    # this function write indirect call that needs to resolve into a file, then we can work on it later
    def outout_indirect_to_resolve(self):
        f = open("./ind_to_resolve/ind_callouts.log", 'w+')
        for _, callout in self.ind_callouts.items():
            f.write(f"{callout.caller_symbolic_name}\t{hex(callout.caller_addr)}\t{hex(callout.call_site)}\n")
        f.close()

    # this function write all plt that needs to resolve into a file, then we can work on it later
    def output_plt_to_resolve(self, obj_collection: ObjCollection):
        for obj_name, callouts in self.plt_callouts.items():
            # if the file is already there, skip
            if os.path.exists(f"./plt_to_resolve/{obj_name}.log"):
                print(f"[resolve_plt]: {obj_name} already exists, skip")
                continue
            obj = obj_collection.get_owner_obj(obj_name)
            if obj is None:
                print(f"[resolve_plt]: Cannot find {obj_name} in shared library list") # this should not happen since the process_plt_call_out already checked
                continue
            if obj.cfg is None:
                obj.cfg = obj.load_or_create_cfg()
            output_file = open(f"./plt_to_resolve/{obj_name}.log", 'w+')
            for _, callout in callouts.items():
                real_func = obj.cfg.functions.get(callout.addr)
                if real_func is None:
                    print(f"[resolve]: Cannot find function at {hex(callout.addr)} in {obj_name}")
                    pdb.set_trace()
                    continue
                callout.symbolic_name2 = real_func.name
                output_file.write(f"{callout.symbolic_name}\t{callout.symbolic_name2}\t{hex(callout.addr)}\n")
                print(f"[resolve_plt]: Resolved PLT entry {callout.symbolic_name} to {callout.symbolic_name2} in {obj_name} at {hex(callout.addr)}")
            output_file.close()
        return



    
