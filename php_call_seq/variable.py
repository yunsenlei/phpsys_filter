import re
import enum
from utils import is_literal

class VariableScope(enum.Enum):
    GLOBAL = 0
    LOCAL = 1

# more accurately, this should be called ClassVaraible
class Variable:
    def __init__(self):
        self.var_scope = VariableScope.LOCAL
        self.var_name = ""
        self.class_name = ""
        self.var_id = -1
        self.def_by = -1
    
    def __str__(self):
        return self.var_name
    
    def __repr__(self):
        return self.var_name

    @classmethod 
    # str_repr is of format "Var#id<$varname>"
    def from_id_name_str(cls, str_repr: str):
        v = cls()
        match = re.match(r"Var#(\d+)<\$([a-zA-Z_][a-zA-Z0-9_]*)>", str_repr)
        if match:
            v.var_id = int(match.group(1), 10)
            v.var_name = match.group(2)
        else:
            raise ValueError(f"[Variable::init]: Invalid variable representation: {str_repr}")
        return v

    @classmethod
    # str_repr is a varaiable name string, this is usually used to create a global variable 
    # where Terminals_Global does not assign id to variable
    def from_literal(cls, str_repr: str):
        _, var_name = is_literal(str_repr)
        v = cls()
        v.var_name = var_name
        return v

    @classmethod
    def get_var_id_from_str(cls, s: str):
        v = cls()
        match = re.match(r"Var#(\d+)<\$([a-zA-Z_][a-zA-Z0-9_]*)>", s)
        if match:
            return int(match.group(1), 10)
        else:
            return -1

    @classmethod
    def get_var_name_from_str(cls, s: str): 
        match = re.match(r"Var#(\d+)<\$([a-zA-Z_][a-zA-Z0-9_]*)>", s)
        if match:
            return match.group(2)
        else:
            return ""

class GlobalVariable:
    def __init__(self, var_name: str):
        self.var_name = var_name
        self.var_type = ""
