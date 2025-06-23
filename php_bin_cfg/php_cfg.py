import pdb
import os
import re
from typing import Dict, Tuple
from angr.knowledge_plugins.functions.function import Function
import system_calls
from angrutils import plot_func_graph
from php_func import PHPFunction, ExternFunction, ContainSyscall, prune_cfg, gen_syscall_seqs_from_call_seqs
from php_bin import PHPBin
from utils import read_enumed_func
from shared_object import ObjCollection
from func_collection import FuncCollection
from callout_collection import CallOutResolver
from process_libs import process_lib_functions

if __name__ == "__main__":
    # Before conducting any analyses, let's first load all realated binaries and run CFG anaylsis on realted files
    binary_basename = "php-fpm"
    php_bin = PHPBin("/home/yslei/php-src/sapi/fpm/php-fpm", "./proj_dir/php_bin.pickle", "./cfg_dir/php_cfg.pickle")
    shared_objects = ObjCollection({name.rpartition('.so')[0]: elf_obj 
        for name, elf_obj in php_bin.proj.loader.shared_objects.items() if ".so" in name})
    api_func_info, _ = read_enumed_func("./enumfunc.log") # generated from the enum_func PHP extension
    fc = FuncCollection()
    total_func_ref = 0
    undefined_func_symbol = 0
    success_pruned_cfg = 0
    sub_fn_log = open("sub_fn_log.txt", "w")

    # Go through all function references within the PHP binary, skip duplicated function names
    for ref_addr, fn in php_bin.cfg.functions.items(): # fn: Function
        total_func_ref += 1
        print(f"Function {fn.name} reference at {hex(ref_addr)}")
        
        if fn.name == "UnresolvableJumpTarget" or fn.name == "UnresolvableCallTarget":
            continue
        
        pattern = re.compile(f'sub_{hex(ref_addr)[2:]}')
        if pattern.match(fn.name):
            continue

        # a plt entry address, we will process this later inside of its caller function
        if fn.is_plt:
            continue

        # a system wrapper function, which should also be a plt entry, but somehow the is_plt is not set 
        if fn.is_syscall:
            continue

        if hash((fn.addr, "php-fpm")) in fc.funcs or hash((fn.addr, "php-fpm")) in fc.api_funcs:
            continue

        func_sym = php_bin.proj.loader.find_symbol(fn.addr)
        if func_sym is None:
           pdb.set_trace()
           print(f"Cannot find function {fn.name} in symbol table")
           continue

        print(f"Creating PHP function {fn.name}...") 
        # first determine if the symbol is in the scope of the php-fpm
        # so that we can get the correct relative addresss and determine if it is a API func
        if func_sym.owner.binary_basename == binary_basename:
            assert(php_bin.proj.loader.main_object.mapped_base == func_sym.owner.mapped_base) # for debug
            php_fn = PHPFunction(fn, php_bin, shared_objects)
            func_rela_addr = fn.addr - php_bin.proj.loader.main_object.mapped_base
            if func_rela_addr in api_func_info:
                php_names = api_func_info[func_rela_addr]
                print(f"Add API function {php_fn.symbolic_name} at {hex(func_rela_addr)}")
                fc.add_api_func(php_names, php_fn)
            else: # not an API function, but still defined in the php-fpm
                fc.add_func(php_fn)
        else:
            owner_so_name = os.path.basename(func_sym.owner.binary).rpartition('.so')[0]
            owner_so = shared_objects.objs.get(owner_so_name, None)
            if owner_so is None:
                print(f"Cannot find shared object {func_sym.owner.binary} in our shared_objects list")
                continue
            extern_fn = ExternFunction(func_sym, owner_so) 
            print(f"Add external function {extern_fn.symbolic_name} at {hex(func_sym.rebased_addr)}")
            fc.add_extern_func(extern_fn)
    pdb.set_trace()

    # resolve all plt call out in the function, start with non-api functions
    cr = CallOutResolver()
    cr.collect_plt_callouts(fc)
    cr.output_plt_to_resolve(shared_objects)
    pdb.set_trace()
    lib_funcs = process_lib_functions(shared_objects)
    assert(len(set(fc.api_funcs.keys()).intersection(lib_funcs.keys())) == 0)
    all_php_fn = fc.api_funcs | fc.funcs
    f = open("php_api_syscall_set.log", "w+")
    for api_func in fc.api_funcs.values():
        api_func.get_syscall_set(lib_funcs, all_php_fn)
        f.write(f"{api_func.symbolic_name}\t{api_func.syscall_set}\n")
    f.close()
    pdb.set_trace()
