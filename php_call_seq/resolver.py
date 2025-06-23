import re
from typing import Any, Dict, Tuple, Callable, Optional, TypedDict
from variable import Variable
from ast_node import CallAstNode
from php_func import PhpFunction
from php_script import PhpScript
from utils import is_literal, get_var_id_from_str, is_named_var

class ResolveContext(TypedDict):
    phpfunc: PhpFunction
    script: Optional[PhpScript]

class ResolveFunc:
    def __init__(self, name, func:Callable[[CallAstNode, ResolveContext], Tuple[str, bool]]):
        self.name = name
        self.func = func

    def __call__(self, node: CallAstNode, context: ResolveContext) -> Tuple[str, bool]:
        return self.func(node, context)

class Resolver:
    def __init__(self):
        self._resolve_heuristics: Dict[str, ResolveFunc] = {}
  
    def get_resolve_method(self, name):
        return self._resolve_heuristics[name]
    
    def add_resolve_method(self, name: str, func: Callable[[CallAstNode, ResolveContext], Any]):    
        self._resolve_heuristics[name] = ResolveFunc(name, func)
    
    def find_resolve_method(self, _: CallAstNode) -> ResolveFunc:
        return self._resolve_heuristics['default']

    def resolve(self, unresolved_node: CallAstNode, context: Dict):
        pass

class ClassNameResolver(Resolver):
    def __init__(self):
        super().__init__()
        self.add_resolve_method('default', self.default_resolve)
        self.add_resolve_method('resolve_this', self.resolve_this)
        self.add_resolve_method('resolve_var_def', self.resolve_var_def)

    def find_resolve_method(self, node: CallAstNode)-> ResolveFunc:
        if node.type == "Expr_MethodCall":
            if node.attrs['var'] == "this<$this>":
                return self.get_resolve_method('resolve_this')
            elif is_named_var(node.attrs['var']):
                return self.get_resolve_method('resolve_var_def')
        return self.get_resolve_method('default')
    

    def resolve(self, unresolved_node: CallAstNode, context: ResolveContext):
        resolve_func = self.find_resolve_method(unresolved_node)
        return resolve_func(unresolved_node, context)
    

    # The methods below are class name resolving heuristics

    # default resolve method, called when no suitable resolve method is found
    def default_resolve(self, __c: CallAstNode, __f: ResolveContext):
        return "", False
    
    # a method call is made using $this->method(), this function find the class name of the function
    def resolve_this(self, _: CallAstNode, context: ResolveContext):
        return context['phpfunc'].class_name, True


    # a method call's class part is a variable, this function find how the variable is defined and get the class name 
    def resolve_var_def(self, node: CallAstNode, context: ResolveContext):
        # find the var's definition locally (in the function)
        local_func = context['phpfunc']
        var_id = Variable.get_var_id_from_str(node.attrs['var'])
        if var_id == -1:
            print(f"[resolve_var_def]: cannot parse the variable id from the var attribute {node.attrs}")
            return "", False
        
        # check if the variable is defined in the function
        if var_id in local_func.named_local_vars:
            var = local_func.named_local_vars[var_id]
            def_by = var.def_by
            if def_by == 0:  # defined by this<$this>
                return local_func.class_name, True
            elif def_by in local_func.exprs:
                def_expr = local_func.exprs[def_by]
                resolved_class_name = def_expr.get_class_name_from_expr()
                if resolved_class_name == "":
                    return "", False
                else:
                    # print(f"[resolve_var_def]: call node {node.attrs} class {var} defined by expression {def_expr.type} {def_expr.attrs}")
                    return resolved_class_name, True
            else:
                print(f"[resolve_var_def]: cannot find the expression that defines the variable {var}")
                return "", False

        # TODO: check if the variable is defined in the script or imported from other scripts
        var_name = Variable.get_var_name_from_str(node.attrs['var'])
        return "", False


def resolve_call_nodes_in_func(func: PhpFunction, context: ResolveContext):
    resolver = ClassNameResolver()
    call_nodes = list(func.get_all_call_nodes())
    func.total_call_nodes = len(call_nodes)
    for call_node in call_nodes:
        if call_node.is_call_node_resolved():
            func.resolved_call_nodes += 1
            call_node.resolved = True
            call_node.set_names()
            continue

        if call_node.type == "Expr_MethodCall":
            resolved_class_name, resolved = resolver.resolve(call_node, context)
            if resolved:
                func.resolved_call_nodes += 1
                call_node.resolved = True
                call_node.set_names()
                call_node.class_name = resolved_class_name


# def resolve_calls_in_function(phpfunc: PhpFunction):
#     for call_node in phpfunc.get_all_call_nodes():
#         call_statistic.total_calls += 1
#         if call_node.name == "Expr_FuncCall":
#                 _fn_name = call_node.attrs['name']
#                 is_literal, fn_name = is_name_literal(_fn_name)
#                 if not is_literal:
#                     call_statistic.unresolved_func_call += 1
#                     print(f"unresolved function name: {call_node}")
#         elif call_node.name == "Expr_MethodCall":
#             _class_name = call_node.attrs['var']
#             _me_name = call_node.attrs['name']
#             is_mn_literal, me_name = is_name_literal(_me_name)
#             is_cn_literal, class_name = is_name_literal(_class_name)
#             if not is_mn_literal:
#                 call_statistic.unresolved_method_call += 1
#                 print("unresolved method name: {}".format(call_node))
#             if not is_cn_literal:
#                 class_name = resolve_class_name(phpfunc, call_node, 'var')
#                 if class_name == "unknown":
#                     call_statistic.unresolved_class_name_in_method_call += 1
#                     print(f"unresolved class name in method call {call_node}")
#         elif call_node.name == "Expr_StaticCall":
#             _class_name = call_node.attrs['class']
#             _fn_name = call_node.attrs['name']
#             is_cn_literal, class_name = is_name_literal(_class_name)
#             is_fn_literal, fn_name = is_name_literal(_fn_name)
#             if not is_cn_literal:
#                 call_statistic.unresolved_staic_method_call += 1
#                 # print(f"unresolved class name in static call {call_node}")
#             if not is_fn_literal:
#                 call_statistic.unresolved_staic_method_call += 1
#                 # print(f"unresolved function name in static call {call_node}")
#         elif call_node.name == "Expr_NsFuncCall":
#             _ns_name = call_node.attrs["nsName"]
#             _fn_name = call_node.attrs["name"]
#             is_nn_litreral, ns_name = is_name_literal(_ns_name)
#             is_fn_literal, fn_name = is_name_literal(_fn_name)
#             if not is_nn_litreral:
#                 call_statistic.unresolved_ns_func_call += 1
#                 # print(f"unresolved namespace name in ns function call {call_node}")
#             if not is_fn_literal:
#                 call_statistic.unresolved_ns_func_call += 1
#                 # print(f"unresolved function name in ns function call {call_node}")
# 
# 
# def resolve_class_name(phpfunc: PhpFunction, node: AstNode, key: str):
#     _class_name = node.attrs[key]
#     if _class_name == "this<$this>":
#         return phpfunc.class_name
#     elif re.match(r"Var#(\d+)<\$wpdb>", _class_name): # this is a special case for global varialbe
#         return "wpdb"
#     else:
#         return resolve_name(phpfunc, node, key)
# 
# def get_var_id_from_attr(node: AstNode, key: str):
#     _var_id = node.attrs[key]
#     pattern = r"^Var#(\d+)(<(.*)>)?"
#     match = re.match(pattern, _var_id)
#     if not match:
#         return -1 
#     var_id = int(match.group(1), 10)
#     return var_id
# 
# def resolve_name(phpfunc: PhpFunction, node: AstNode, key: str):
#     var_id = get_var_id_from_attr(node, key)
#     if var_id == -1:
#         print(f"cannot parse var_id from {node}")
#         return "unknown"
#     
#     trace_id = var_id 
#     depth = 0 
#     while True:
#         for n in phpfunc.get_all_ast_nodes():
#             if 'result' not in n.attrs:
#                 continue
#             current_id = get_var_id_from_attr(n, 'result')
#             if current_id == trace_id:
#                 depth += 1
#                 name = resolve_from_node(n, phpfunc)
#                 return name        
#         break
#     return "unknown"
# 
# # The 'result' attribute of the node is a variable that mathces the one we are looking for,
# # However, the type of the node determines how we can resolve the name.
# def resolve_from_node(node: AstNode, phpfunc: PhpFunction):
#     if node.name not in call_statistic.direct_unresolved_node_type:
#         call_statistic.direct_unresolved_node_type[node.name] = 0
#     else:
#         call_statistic.direct_unresolved_node_type[node.name] += 1
#     func_ret_type = {"get_current_screen": "WP_Screen", "wp_roles": "WP_Roles", "wp_scripts": "WP_Scripts", "wp_styles": "WP_Styles", "wp_get_theme": "WP_Theme"}
#     if node.name == "Expr_Param":
#         _tmp_name = node.attrs['declaredType']
#         is_literal, tmp_name = is_name_literal(_tmp_name)
#         if not is_literal:
#             return "unknown"
#         else:
#             return tmp_name
#     elif node.name == "Expr_FuncCall":
#         _tmp_name = node.attrs['name']
#         is_literal, func_name = is_name_literal(_tmp_name)
#         if not is_literal:
#             return "unknown"
#         else:
#             if func_name in func_ret_type:
#                 return func_ret_type[func_name]
#             else:
#                 print("unknown function {}".format(func_name))
#                 return "unknown"
#     elif node.name == "Expr_PropertyFetch":
#         obj = node.attrs['var']
#         if obj == "this<$this>":
#             pass
#             # TODO: get definition of the class
#         property = node.attrs['name']
#     return  "unknown"
# 
