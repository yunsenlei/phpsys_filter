from typing import List, Set, Dict
from ast_node import CallAstNode
from php_script import PhpScript
from php_func import PhpFunction
from func_collection import FunctionCollection
from script_collection import ScriptCollection


class PolicyGenerator:
    def __init__(self):
        internal_func_syscall_set: Dict[str, Set[int]] = {} # symbolic name -> set of syscall numbers
        # TODO: read from import file
            
    def script_set(self, s: PhpScript, fc: FunctionCollection):
        main_func = s.defined_functions[""]["main"]
        callouts = list(main_func.get_all_call_nodes())
        internal_callouts: Set[str] = set() 
        processed_user_funcs: Set[PhpFunction] = set()
        stack: List[PhpFunction] = [main_func]

        while len(stack) > 0:
            user_func = stack.pop()
            if user_func in processed_user_funcs:
                continue
            processed_user_funcs.add(user_func)
            callouts = list(user_func.get_all_call_nodes())
            for call in callouts:
                if not call.resolved:
                    continue
                # if the callee function is a user-defined function/method
                user_func = fc.find_user_func(call.class_name, call.func_name)
                if user_func is not None and user_func not in processed_user_funcs:
                    stack.append(user_func)
                    continue
                # if the callee function is an internal function/method
                internal_func = fc.find_internal_func(call.class_name, call.func_name)
                if internal_func is not None:
                    internal_callouts.add(internal_func)
                    continue
        return internal_callouts
