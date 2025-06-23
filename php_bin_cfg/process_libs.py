# for shared objects the PHP binary depends on, we only care about functions that is called by the PHP binary
# this information is stored in file under ./plt_to_resolve
import os
import pdb
from typing import Dict, Set
from lib_func import LibFunction
from shared_object import ObjCollection
from callout import CallOut, CallOutType

def process_lib_functions(shared_objects: ObjCollection)-> Dict[int, LibFunction]:

    callouts: Set[CallOut] = set()
    processed_callouts: Set[CallOut] = set()
    lib_funcs: Dict[int, LibFunction] = {}

    # read through all files in ./plt_to_resolve to initialze the above sets
    plt_call_files = ["./plt_to_resolve/" + f for f in os.listdir("./plt_to_resolve")]
    for f_path in plt_call_files:
        obj_name = os.path.basename(f_path).rpartition(".log")[0]
        owner_obj = shared_objects.get_owner_obj(obj_name)
        if owner_obj is None:
            print(f"cannot find owner obj for {obj_name}")
            pdb.set_trace() # debug
            continue
        owner_obj.cfg = owner_obj.load_or_create_cfg()
        f = open(f_path, 'r')
        lines = f.readlines()
        for line in lines:
            _, resolved_name, addr = line.split('\t')
            addr = int(addr, 16)
            fn = owner_obj.cfg.functions.get_by_addr(addr)
            if fn is None:
                print(f"cannot find function {resolved_name} at addr {hex(addr)}")
                pdb.set_trace() # debug
                continue

            print(f"Creating library function for {fn.name}")
            lib_fn = LibFunction(fn, owner_obj, shared_objects)
            libfn_hash = hash(lib_fn)
            if lib_fn in lib_funcs:
                continue
            lib_funcs[libfn_hash] = lib_fn
            for call in lib_fn.call_outs.values():
                if call.type != CallOutType.RESOLVED_PLT and call.type != CallOutType.DIRECT:
                    continue
                callouts.add(call)

    while callouts:
        print("callouts left:", len(callouts))
        call = callouts.pop()
        if call in processed_callouts:
            continue

        lib_fn = LibFunction.from_callout(call, shared_objects)
        processed_callouts.add(call)

        if lib_fn is None:
            print(f"Cannot create lib function for {call.symbolic_name}")
            pdb.set_trace() # debug
            continue

        print(f"Created library function for {lib_fn.symbolic_name}")
        
        if lib_fn in lib_funcs:
            print(f"Duplicate Library Function")
            pdb.set_trace()
            continue

        libfn_hash = hash(lib_fn)
        lib_funcs[libfn_hash] = lib_fn

        for call in lib_fn.call_outs.values():
            if call.type != CallOutType.RESOLVED_PLT and call.type != CallOutType.DIRECT:
                continue
            if call not in processed_callouts:
                callouts.add(call)

    for _, lib_fn in enumerate(lib_funcs.values()):
        print(f"Processing syscall set for {lib_fn.symbolic_name} .... {_+1}/{len(lib_funcs)}")
        lib_fn.collect_all_syscall_sets(lib_funcs)

    f = open("./syscall_sets.log", "w+")
    for lib_fn in lib_funcs.values():
        f.write(f"{lib_fn.symbolic_name}\t{lib_fn.syscall_set}\n")
    f.close()
    return lib_funcs
