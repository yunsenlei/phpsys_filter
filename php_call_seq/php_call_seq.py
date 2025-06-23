import os
import pdb
import specs
import re
from php_script import PhpScript
from resolver import resolve_call_nodes_in_func
from func_collection import FunctionCollection
from script_collection import ScriptCollection
from policy_generator import PolicyGenerator

def get_api_syscall_mapping(filename):
    syscall_mapping = {}
    # Open the file and read line by line
    with open(filename, 'r') as file:
        for line in file:
            api_func_name = line.split('\t')[0]
            # Extract the numbers within {}
            match = re.search(r'\{(.*?)\}', line)
            if match:
                # Split the matched string into individual numbers and convert them to integers
                system_calls = match.group(1).split(',')
                if api_func_name not in syscall_mapping:
                    syscall_mapping[api_func_name] = system_calls
    return syscall_mapping

if __name__ == "__main__":
    policy_generator = PolicyGenerator()
    spec_file = "./php_cfg/php_ast_nodes.json"
    api_name_file = "/home/yslei/php_bin_cfg/matched_api_funcs.txt"
    specs.get_ast_node_spec(spec_file)
    func_collection = FunctionCollection(api_name_file)
    script_collection = ScriptCollection()
    api_syscall_mapping = get_api_syscall_mapping('./php_api_syscall_sets.log')
    print(api_syscall_mapping)
    dir = "./php_cfg/new_script_cfg/"
    dot_json_files = [os.path.join(dir, f) for f in os.listdir(dir) if f.endswith(".dot_json")]
    loop_func = 0
    for f in dot_json_files:
        try:
            print("processing {}".format(f))
            s = PhpScript.from_cfg_file(f)
            for class_name, funcs in s.defined_functions.items():
                for func_name, func in funcs.items():
                    resolve_call_nodes_in_func(func, {"phpfunc": func, "script": s})
            s.collect_call_resolution_statistic()
            func_collection.add_funcs_from_script(s)
            script_collection.add_script(s)
            # print(f"call resolution:{s.total_resolved_call_num}/{s.total_call_num}\n")
                # main_func = s.defined_functions[""]["main"]
                # print(list(main_func.get_all_call_nodes()))
        except ValueError as e:
            print(e)
    total_syscalls = 0
    total_scripts = 0
    for script in script_collection.scripts.values():
        main_func = script.defined_functions[""]["main"]
        num_calls_in_main = len(list(main_func.get_all_call_nodes()))
        if num_calls_in_main == 0:
            continue
        internal_callouts = policy_generator.script_set(script, func_collection)
        script_syscalls = []
        for internal_api in internal_callouts:
            syscalls = api_syscall_mapping.get(internal_api, [])
            script_syscalls.extend(syscalls) 
        print(script.script_name, len(set(script_syscalls)))
        total_syscalls += len(set(script_syscalls))

        if len(set(script_syscalls)) > 0:
            total_scripts += 1
    print("average system call per script:", float(total_syscalls / total_scripts))

    # print(f"total functions: {call_statistic.total_func}")
    # print(f"total loop functions: {loop_func}")
    # print(f"total calls: {call_statistic.total_calls}")
    # print(f"unresolved static method calls: {call_statistic.unresolved_staic_method_call}")
    # print(f"unresolved method calls: {call_statistic.unresolved_method_call}")
    # print(f"unresolved class name in method calls: {call_statistic.unresolved_class_name_in_method_call}")
    # print(f"unresolved function calls: {call_statistic.unresolved_func_call}")
    # print(f"unresolved namespace function calls: {call_statistic.unresolved_ns_func_call}")
    # call_statistic.direct_unresolved_node_type = {k: v for k, v in sorted(call_statistic.direct_unresolved_node_type.items(), key=lambda item: item[1], reverse=True)}
    # for key, val in call_statistic.direct_unresolved_node_type.items():
    #     print(f"unresolved node type {key}: {val}")
    # for key, val in call_statistic.edge_label_type.items():
    #     print(f"edge label type {key}: {val}")
