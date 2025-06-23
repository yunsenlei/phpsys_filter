from itertools import chain, islice
import json
from os.path import basename

from typing import Dict
from utils import BlockType, parse_block_name, parse_function_name
from concurrent.futures import ProcessPoolExecutor
from php_func import PhpFunction
from basic_block import PhpBasicBlock
from variable import Variable


class PhpScript:
    def __init__(self, cfg_file: str):
        self.script_name = basename(cfg_file).replace(".dot_json", "")
        self.cfg_json = {}
        self.defined_functions: Dict[str, Dict[str, PhpFunction]] = {}
        self.defined_global_vars: Dict[str, Variable] = {}
        self.contain_global_code = False # if the script contains global code (not in a function)
        self.total_call_num = 0
        self.total_resolved_call_num = 0

    @classmethod
    def from_cfg_file(cls, cfg_file):
        php_script = cls(cfg_file)
        php_script.cfg_json = cls._read_and_load_cfg_file(cfg_file)
        if php_script.cfg_json is None:
            raise ValueError(f"Script {php_script.script_name} is not loaded to create CFG")

        func_dict: Dict[int, PhpFunction] = {} # a temporary dict to store functions defined in a script
        # get basic blcoks  (node of the cfg), and store them into different group basde on which function they belong to
        _basic_blocks = php_script.cfg_json['objects'] # a list of basic block dict
        for b in _basic_blocks:
            b_name = b['name']
            b_type, func_id = parse_block_name(b_name)
            if func_id not in func_dict:
                func_dict[func_id] = PhpFunction() # create an empty PhpFunction object 
            php_func = func_dict[func_id]

            if b_type == BlockType.HEADER: # for header block, we update the function name
                class_name, func_name = parse_function_name(b['label'])
                php_func.class_name = class_name
                php_func.func_name = func_name
                php_func.header_block_id = b['_gvid']
            elif b_type == BlockType.BLOCK: # for normal block, create PhpBasicBlock and store it into the function it belongs to
                try:
                    bb = PhpBasicBlock.from_dict(b)
                    block_id = b['_gvid']
                    php_func.basic_blocks[block_id] = bb
                except Exception as e:
                    print(f"Error when parsing block {b['name']} for function {php_func.func_name}, {e}")
                    continue
        
        # for each functions in the script, sort the basic blocks by their id
        for _, f in func_dict.items():
            f.basic_blocks = dict(sorted(f.basic_blocks.items(), key=lambda x: x[0]))

        # get edges of the cfg and assign it to the corresponding function
        _edges = php_script.cfg_json['edges']
        for e in _edges:
            for _, f in func_dict.items():
                if f.is_edge_belong_to_function((e['tail'], e['head'])):
                    if 'label' in e:
                        if e['label'] == "defaultBlock": # we don't need to add this edge and need to remove the tail node
                            del(f.basic_blocks[e['head']])
                        else:
                            f.edges.append((e['tail'], e['head'], e['label']))
                    else:
                        f.edges.append((e['tail'], e['head'], ""))
                    break # one edge can only belong to one function, so we can break the loop here

        # create the cfg for each function in the script
        for _, f in func_dict.items():
            f.create_cfg()
            f.create_exprs() # must populate expression before parsing variables
            f.create_global_vars() # must parse global before local
            f.create_var_defs()
            f.create_call_graph_from_cfg()
        
        # move functions from func_dict to defined_function, the func_id is not useful anymore
        for _, f in func_dict.items():
            if f.class_name not in php_script.defined_functions:
                php_script.defined_functions[f.class_name] = {}
            php_script.defined_functions[f.class_name][f.func_name] = f

        # look for the "main" function of the script and populate the defined_global_vars
        if "" in php_script.defined_functions and "main" in php_script.defined_functions[""]:
            php_script.contain_global_code = True
            main_func = php_script.defined_functions[""]["main"]
            # the main func's named_local_var is global var
            for v in main_func.named_local_vars.values():
                php_script.defined_global_vars[v.var_name] = v # a variable might be assigned multiple times, we use the last one
        return php_script
    
    def collect_call_resolution_statistic(self):
        for method_list in self.defined_functions.values():
            for func in method_list.values():
                self.total_call_num += func.total_call_nodes
                self.total_resolved_call_num += func.resolved_call_nodes

    @staticmethod
    def _read_and_load_cfg_file(cfg_file: str):
        try:
            with open(cfg_file, 'r', encoding='utf-8', errors='replace') as f:
                cfg_json = json.load(f)
        except FileNotFoundError:
            cfg_json = None
            print("ScriptCfg: cannot find cfg file: {}".format(cfg_file))
        except json.decoder.JSONDecodeError as e:
            cfg_json = None
            print("ScriptCfg: JSONDecodeError, cannot decode cfg file: {} at position {} {}".format(cfg_file, e.pos, e.msg))
        except UnicodeDecodeError as e: 
            cfg_json = None
            print("SciprtCfg: UnicodeDecodeError, cannot decode cfg file: {} from {} to {} because {}".format(cfg_file, e.start, e.end, e.reason))
 
        return cfg_json
