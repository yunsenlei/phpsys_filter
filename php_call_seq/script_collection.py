from typing import Dict, Optional
from php_script import PhpScript

class ScriptCollection:
    def __init__(self):
        self.scripts: Dict[str, PhpScript] = {}
    
    def add_script(self, script: PhpScript):
        self.scripts[script.script_name] = script
    
    def find_script(self, script_name: str) -> Optional[PhpScript]:
        if script_name in self.scripts:
            return self.scripts[script_name]
        return None
