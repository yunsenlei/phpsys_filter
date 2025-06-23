from typing import Dict, Set, List, Tuple
from php_func import ExternFunction, PHPFunction
from random import choice
from utils import read_enumed_func

def get_all_funcs_from(where: List[PHPFunction], prop: str, val) -> List[PHPFunction]:
    if "." in prop:
        props = prop.split(".")
        if len(props) != 2:
            return []
        matched_funcs = [fn for fn in where if getattr(getattr(fn, props[0]), props[1]) == val]
    else:
        matched_funcs = [fn for fn in where if getattr(fn, prop) == val]
    return matched_funcs

class FuncCollection:
    def __init__(self):
        self.api_funcs: Dict[int, PHPFunction] = {} # {hash: PHPFunction}
        self.funcs: Dict[int, PHPFunction] = {} # {hash: PHPFunction}
        self.ext_funcs: Dict[str, ExternFunction] = {} # used to store external functions referenced in PHP, defined externally
        self.class_method_map: Dict[str, Dict[str, PHPFunction]] = {} # store same function information, easier to query by name
        self.api_func_nums = 0
        self.total_defined_func = 0
        self.contain_indirect_call_func = 0
        self.direct_contain_syscall_api = 0
        self.indirect_contain_syscall_api = 0
        self.no_contain_syscall_api = 0
    
    def get_statistics(self):
        self.total_defined_func = len(self.funcs) + self.api_func_nums + len(self.ext_funcs)
    
    def __str__(self):
        return f"""
        Total defined function: {self.total_defined_func}
        PHP API function: {self.api_func_nums}
        PHP non-API function: {len(self.funcs)}
        External referenced function: {len(self.ext_funcs)}
        Direct contain syscall function: {self.direct_contain_syscall_api}
        Indirect contain syscall function: {self.indirect_contain_syscall_api}
        No contain syscall function: {self.no_contain_syscall_api}
        """

    def add_api_func(self, php_names: List[Tuple[str, str]], php_func: PHPFunction):
        php_func.php_names = php_names
        phpfunc_hash = hash(php_func)
        if phpfunc_hash in self.api_funcs:
            return

        self.api_funcs[phpfunc_hash] = php_func
        for class_name, func_name in php_names:
            if class_name not in self.class_method_map:
                self.class_method_map[class_name] = {}
            self.class_method_map[class_name][func_name] = php_func
        self.api_func_nums += len(php_names)

    def add_func(self, php_func: PHPFunction):
        phpfunc_hash = hash(php_func)
        if phpfunc_hash in self.funcs:
            return
        self.funcs[phpfunc_hash] = php_func
    
    def add_extern_func(self, ext_func: ExternFunction):
        if ext_func.symbolic_name in self.ext_funcs:
            return
        self.ext_funcs[ext_func.symbolic_name] = ext_func

    def output_matched_api_funcs(self, file_path):
        _, enumed_api_funcs = read_enumed_func("./enumfunc.log")
        with open(file_path, 'w+') as f:
            for class_name, funcs in enumed_api_funcs.items():
                f.write(f"CLASS\t{class_name}\n")
                for func_name in funcs:
                    if class_name in self.class_method_map and func_name in self.class_method_map[class_name]:
                        f.write(f"\t\t{func_name}\t{self.class_method_map[class_name][func_name].symbolic_name}\n")
                    else:
                        f.write(f"\t\t{func_name}\tNOT FOUND\n")

    # def get_all_api_funcs(self, prop: str, val):
    #     all_api_funcs = []
    #     for _, funcs in self.api_funcs.items():
    #         for func in funcs.values():
    #             all_api_funcs.append(func)
    #     return get_all_funcs_from(all_api_funcs, prop, val)

    # def get_all_funcs(self, prop: str, val):
    #     all_funcs = list(self.funcs.values())
    #     return get_all_funcs_from(all_funcs, prop, val)

    # def get_a_api_func(self, prop: str, val):
    #     # return a random API function that has property equals to val
    #     funcs = self.get_all_api_funcs(prop, val) 
    #     random_func = choice(funcs)
    #     return random_func
    # 
    # def get_a_func(self, prop: str, val):
    #     # return a random function that has property equals to val
    #     funcs = self.get_all_funcs(prop, val)
    #     random_func = choice(funcs)
    #     return random_func
