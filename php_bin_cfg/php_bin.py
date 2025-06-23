import os
import pickle
import angr

class PHPBin:
    def __init__(self, bin_path: str, proj_pickle: str, cfg_pickle: str):
        self.name = "php-fpm" 
        self.bin_path = os.path.abspath(bin_path)
        proj_pickle = os.path.abspath(proj_pickle)
        cfg_pickle =  os.path.abspath(cfg_pickle)
        # Load the main project and its CFG
        self.proj = self._load_or_create_project(self.bin_path, proj_pickle)
        self.cfg = self._load_or_create_cfg(self.proj, cfg_pickle)
        # Discver all shared libraries used by the main project and the all dependent libraries of the shared libraries
        self.relocs = {reloc.relative_addr: reloc for reloc in self.proj.loader.main_object.relocs}

    def _load_or_create_cfg(self, proj, cfg_pickle: str):
        # Load or create the CFG
        try:
            with open(cfg_pickle, 'rb') as f:
                return pickle.load(f)
        except FileNotFoundError:
            cfg = proj.analyses.CFGFast(show_progressbar=True)
            with open(cfg_pickle, 'wb') as f:
                pickle.dump(cfg, f)
            return cfg

    def _load_or_create_project(self, bin_path: str, proj_pickle: str):
        # Load of create the project
            try:
                with open(proj_pickle, 'rb') as f:
                    return pickle.load(f)
            except FileNotFoundError:
                proj = angr.Project(bin_path, auto_load_libs=True)
                with open(proj_pickle, 'wb') as f:
                    pickle.dump(proj, f)
                return proj


