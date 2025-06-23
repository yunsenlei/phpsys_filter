import json
from enum import Enum
from typing import Dict, List

class Indent(Enum):
    HDR_INDENT = 8
    ATTR_INDENT = 12

class CallStatictics:
    def __init__(self):
        self.unresolved_func_call = 0
        self.unresolved_class_name_in_method_call = 0
        self.unresolved_method_call = 0
        self.unresolved_staic_method_call = 0
        self.unresolved_ns_func_call = 0
        self.total_calls = 0
        self.direct_unresolved_node_type = {}
        self.edge_label_type = {}
        self.total_func = 0
        self.loop_func = 0

def get_ast_node_spec(spec_file):
    global ast_node_specs
    with open(spec_file, "r") as f:
        tmp_spec_list = json.load(f)['astnodes']
        for node_spec in tmp_spec_list:
            key = node_spec['nodename']
            val = node_spec['attrs']
            ast_node_specs[key] = val

def get_api_func_names(api_name_file):
    global api_func_names
    with open(api_name_file, "r") as f:
        current_class_name = ""
        for line in f:
            if line.startswith("CLASS\t"):
                _, classname = line.split("\t", 1)
                current_class_name = classname.strip()
            elif line.startswith("\t\t"):
                func_name, symbolic_name = line[2:].split("\t", 1)
                func_name = func_name.strip()
                symbolic_name = symbolic_name.strip()
                if current_class_name not in api_func_names:
                    api_func_names[current_class_name] = {}
                api_func_names[current_class_name][func_name] = symbolic_name

call_statistic = CallStatictics()
ast_node_specs = {}
api_func_names: Dict[str, Dict[str, str]] = {}
call_ast_node_types: List[str] = [ "Expr_FuncCall", "Expr_MethodCall", "Expr_StaticCall", "Expr_NsFuncCall"]

