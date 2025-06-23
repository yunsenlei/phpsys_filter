import re
import enum
from typing import Dict
from utils import is_literal
from specs import call_ast_node_types

class AstNode:
    def __init__(self, type: str, attrs: Dict):
        # create phi node differently
        match = re.match(r'Var#(\d+)(<.*>)? = Phi\(.*\)', type)
        if match:
            self.type = "Phi"
            self.attrs = {}
            self.attrs['expr'] = type
            self.attrs['result'] = f"Var#{match.group(1)}"
            return

        self.type = type
        self.attrs = attrs
    
    @staticmethod
    def is_call_node(s: str):
        if s == "Expr_FuncCall":
            return True
        elif s == "Expr_MethodCall":
            return True
        elif s == "Expr_StaticCall":
            return True
        elif s == "Expr_NsFuncCall":
            return True
        return False

    def is_valid_assign_node(self):
        if self.type != "Expr_Assign":
            return False
        if 'var' not in self.attrs or 'expr' not in self.attrs or 'result' not in self.attrs:
            return False
        return True

    def __repr__(self):
        return f"{self.type} {self.attrs['name'] if 'name' in self.attrs else ''}"

    def __str__(self) -> str:
        return f"{self.type} {self.attrs['name'] if 'name' in self.attrs else ''}"

    def get_class_name_from_expr(self):
        if self.type == "Expr_New":
            class_name = self.attrs['class']
            cn_literal, class_name = is_literal(class_name)
            if cn_literal:
                return class_name
            else:
                return ""
        else:
            return ""


class CallType(enum.Enum):
    USER = 1
    INTERNAL = 2
    UNKNOWN = 3

class CallAstNode(AstNode):
    def __init__(self, type: str, attrs: Dict):
        if type not in call_ast_node_types:
            raise ValueError("CallAstNode: not a call node, failed to create CallAstNode")
        super().__init__(type, attrs)
        self.ns_name = ""
        self.class_name = ""
        self.func_name = ""
        self.resolved = False
        self.call_type = CallType.UNKNOWN

    def __repr__(self):
        r = ""
        if self.type == "Expr_NsFuncCall":
            r = self.ns_name + "::" + self.func_name
        elif self.type == "Expr_StaticCall":
            r = self.class_name + "::" + self.func_name
        elif self.type == "Expr_MethodCall":
            r = self.class_name + "::" + self.func_name
        else:
            r = self.func_name
        return r

    def __str__(self) -> str:
        return self.__repr__()
    
    def is_call_node_resolved(self) -> bool:
        if self.type == "Expr_FuncCall":
            is_fn_literal, _ = is_literal(self.attrs['name'])
            if not is_fn_literal:
                return False
            else:
                return True
        elif self.type == "Expr_MethodCall":
            is_cn_literal, _ = is_literal(self.attrs['var'])
            is_mn_literal, _ = is_literal(self.attrs['name'])
            if is_cn_literal and is_mn_literal:
                return True
            else: 
                return False
        elif self.type == "Expr_StaticCall":
            is_cn_literal, _ = is_literal(self.attrs['class'])
            is_mn_literal, _ = is_literal(self.attrs['name'])
            if is_cn_literal and is_mn_literal:
                return True
            else:
                return False
        else:
            is_ns_literal, _ = is_literal(self.attrs['nsName'])
            is_fn_literal, _ = is_literal(self.attrs['name'])
            if is_ns_literal and is_fn_literal:
                return True
            else:
                return False

    def set_names(self):
        unresolved = "[unresolved]"
        if self.type == "Expr_NsFuncCall":
            ns_literal, ns_name = is_literal(self.attrs['nsName'])
            fn_literal, func_name = is_literal(self.attrs['name'])
            if not ns_literal:
                self.ns_name = unresolved
            else:
                self.ns_name = ns_name
            if not fn_literal:
                self.func_name = unresolved
            else:
                self.func_name = func_name
        elif self.type == "Expr_StaticCall":
            cn_literal, class_name = is_literal(self.attrs['class'])
            mn_literal, method_name = is_literal(self.attrs['name'])
            if not cn_literal:
                self.class_name = unresolved
            else:
                self.class_name = class_name
            if not mn_literal:
                self.func_name = unresolved
            else:
                self.func_name = method_name
        elif self.type == "Expr_MethodCall":
            cn_literal, class_name = is_literal(self.attrs['var'])
            mn_literal, method_name = is_literal(self.attrs['name'])
            if not cn_literal:
                self.class_name = unresolved
            else:
                self.class_name = class_name
            if not mn_literal:
                self.func_name = unresolved
            else:
                self.func_name = method_name
        else:
            fn_literal, func_name = is_literal(self.attrs['name'])
            if not fn_literal:
                self.func_name = unresolved
            else:
                self.func_name = func_name
