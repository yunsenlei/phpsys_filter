from typing import Dict, Optional
from php_script import PhpScript
from php_func import PhpFunction

class FunctionCollection:
    def __init__(self, api_name_file):
        self.internal_funcs: Dict[str, str] = {} # map function name to their symbolic name
        self.internal_classes: Dict[str, Dict[str, str]] = {} # map class::method to their symbolic name
        self.functions: Dict[str, Dict[str, PhpFunction]] = {}

        # populate the internal function names from file 
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
                    if current_class_name == "":
                        self.internal_funcs[func_name] = symbolic_name
                    else:
                        if current_class_name not in self.internal_classes:
                            self.internal_classes[current_class_name] = {}
                        self.internal_classes[current_class_name][func_name] = symbolic_name

    def add_funcs_from_script(self, script: PhpScript):
        for class_name, methods in script.defined_functions.items():
            if class_name not in self.functions:
                self.functions[class_name] = {}
            for method_name, method in methods.items():
                if class_name == "" and method_name == "main":
                    continue
                self.functions[class_name][method_name] = method

    def find_user_func(self, class_name: str, method_name: str) -> Optional[PhpFunction]:
        if class_name in self.functions:
            if method_name in self.functions[class_name]:
                return self.functions[class_name][method_name]
        return None

    def find_internal_func(self, class_name: str, method_name: str):
        if class_name == "":
            return self.internal_funcs.get(method_name, None)
        else:
            if class_name in self.internal_classes:
                return self.internal_classes[class_name].get(method_name, None)
        return None
