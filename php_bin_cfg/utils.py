import pickle
from typing import Dict, Tuple, List, Optional
from angr import Project
import angr

def read_enumed_func(file_path):
    # a single function can be used as a method in different class due to inheritance
    addr_to_func_info: Dict[int, List[Tuple[str, str]]] = {} # addr -> [(class_name, func_name)]
    func_to_sym_name: Dict[str, Dict[str, str]] = {} # class_name -> func_name -> symbolic_name
    current_class_name = ""
    with open(file_path, 'r') as f:
        for line in f:
            line = line.strip()
            if line.startswith("CLASS\t"):
                _, class_name = line.split("\t", 1)
                current_class_name = class_name.strip()
            elif "\t" in line:
                func_name, addr = line.split("\t", 1)
                addr = int(addr, 16)
                func_name = func_name.strip()
                if addr not in addr_to_func_info:
                    addr_to_func_info[addr] = []
                addr_to_func_info[addr].append((current_class_name, func_name))
                if current_class_name not in func_to_sym_name:
                    func_to_sym_name[current_class_name] = {}
                func_to_sym_name[current_class_name][func_name] = "" # we don't know the symbolic name yet
    return addr_to_func_info, func_to_sym_name


def load_or_create_cfg(proj, cfg_pickle: str):
    # Load or create the CFG
    try:
        with open(cfg_pickle, 'rb') as f:
            return pickle.load(f)
    except FileNotFoundError:
        cfg = proj.analyses.CFGFast(show_progressbar=True)
        with open(cfg_pickle, 'wb') as f:
            pickle.dump(cfg, f)
        return cfg

def load_or_create_project(bin_path: str, proj_pickle: str) -> Project:
    # Load of create the project
        try:
            with open(proj_pickle, 'rb') as f:
                return pickle.load(f)
        except FileNotFoundError:
            proj = angr.Project(bin_path, auto_load_libs=True)
            with open(proj_pickle, 'wb') as f:
                pickle.dump(proj, f)
            return proj

def load_project(proj_pickle: str) -> Optional[Project]:
        try:
            with open(proj_pickle, 'rb') as f:
                return pickle.load(f)
        except FileNotFoundError:
            return None
