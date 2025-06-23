import pickle
from typing import Dict, Optional
from angr.analyses.cfg.cfg_fast import CFGFast
from angr import Project
from cle.backends.elf.elf import ELF
from utils import load_or_create_project

class SharedObject:
    def __init__(self, name: str ,bin_path: str, proj: Project, cfg_pickle: str):
        self.name = name
        self.bin_path = bin_path
        self.proj = proj
        self.cfg_pickle = cfg_pickle
        self.relocs = {reloc.relative_addr: reloc for reloc in proj.loader.main_object.relocs}
        self.cfg = None # type: Optional[CFGFast]
        # self.cfg: CFGFast = self.load_or_create_cfg(proj, cfg_pickle)
 
    def load_or_create_cfg(self):
        print(f"[load_or_create_cfg]: load or create cfg for {self.name}")
        try:
            with open(self.cfg_pickle, 'rb') as f:
                return pickle.load(f)
        except FileNotFoundError:
            cfg = self.proj.analyses.CFGFast(show_progressbar=True)
            with open(self.cfg_pickle, 'wb') as f:
                pickle.dump(cfg, f)
            return cfg

class ObjCollection:
    def __init__(self, undiscovered: Dict[str, ELF]) -> None:
        self.objs: Dict[str, SharedObject] = {}
        self.discover_libraries(undiscovered)

    def discover_libraries(self, undiscovered: Dict[str, ELF]):
        while undiscovered:
            name, elf_obj = undiscovered.popitem()
            if name in self.objs:
                continue
            # Create a new project for the library
            lib_proj = load_or_create_project(elf_obj.binary, f"./proj_dir/{name}.pickle")
            # Add the library to the discovererd list
            self.objs[name] = SharedObject(name, elf_obj.binary, lib_proj, f"./cfg_dir/{name}.pickle") # CFG is created on demand
            print(f"Lib {name} created and mark as discovered")
            # Add the library's dependencies to the undiscovered list
            for dep_name, dep_elf in lib_proj.loader.shared_objects.items():
                dep_name = dep_name.rpartition('.so')[0]
                if ".so" in dep_name and dep_name not in self.objs and dep_name not in undiscovered:
                    undiscovered[dep_name] = dep_elf

    def get_owner_obj(self, name: str) -> Optional[SharedObject]:
        return self.objs.get(name, None)
