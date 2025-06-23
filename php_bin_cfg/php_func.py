from itertools import product
import warnings
import capstone
import enum
import system_calls
import pdb
from typing import Dict, Any, List, Tuple, Union, Set
import networkx as nx
from cle import Symbol
from angr.knowledge_plugins.functions.function import Function
from angrutils import plot_func_graph
from angr.codenode import BlockNode, HookNode
from php_bin import PHPBin
from shared_object import SharedObject, ObjCollection
from callout import CallOut, CallOutType
from lib_func import LibFunction

class ContainSyscall(enum.Enum):
    SYSCALL = 0 
    DIRECT = 1
    INDIRECT = 2
    NONE = 3
    UNKNOWN = 4

class PHPFunction:
    # a PHPFunction representation is created with a function symbol, a Function (a function in angr)
    def __init__(self, fn: Function, owner_obj: PHPBin, obj_collection: ObjCollection) -> None:
        self.owner_obj_name = owner_obj.name # for php function, the owner obj is the PHP bianry
        self.symbolic_name: str = fn.name
        self.addr: int = fn.addr
        self.orig_fn: Function = fn

        self.php_names: List[Tuple[str, str]] # [(class_name, func_name)], a function can be used as method for different class due to inheritance
        self.entry_nodes: List = []
        self.call_outs: Dict[int, CallOut]  = {} # {call_site: CallOut}
        self.contain_syscall = ContainSyscall.UNKNOWN
        self.cfg_asyclic = False
        self.cfg: nx.DiGraph = self.__create_func_cfg(fn, owner_obj, obj_collection)
        self.cfg_node_num = len(self.cfg.nodes())
        self.pruned_cfg = nx.DiGraph()
        self.pruned_cfg_node_num = 0
        self.call_sequences: List[List[str]] = []
        self.syscall_set: Set[int] = set()

    def __eq__(self, other): 
        if not isinstance(other, PHPFunction):
            return False
        return self.owner_obj_name == other.owner_obj_name and self.addr == other.addr

    def __hash__(self):
        return hash((self.addr, self.owner_obj_name))

    def get_syscall_set(self, lib_funcs: Dict[int, LibFunction], php_funcs: Dict[int, "PHPFunction"]):
        resolve_stack = [self]
        added_plt: List[LibFunction] = []
        added_direct: List["PHPFunction"] = []

        while len(resolve_stack) > 0:
            php_fn = resolve_stack.pop()
            for callout in php_fn.call_outs.values():
                fn_hash = hash((callout.addr, callout.owner_obj_name))
                if callout.type == CallOutType.DIRECT:
                    callee_fn = php_funcs.get(fn_hash)
                    if callee_fn is None:
                        print(f"[PHPFunction::get_syscall_set]: cannot find PHPFunction {callout.symbolic_name} from CallOut in php_funcs")
                        pdb.set_trace() # debug
                        continue
                    if callee_fn not in added_direct:
                        resolve_stack.append(callee_fn)
                        added_direct.append(callee_fn)
                elif callout.type == CallOutType.RESOLVED_PLT:
                    callee_fn = lib_funcs.get(fn_hash) # notice it's looked up from lib_funcs, while above is from php_funcs
                    if callee_fn is None:
                        print(f"[PHPFunction::get_syscall_set]: cannot find LibFunction {callout.symbolic_name} from CallOut in lib_funcs")
                        pdb.set_trace() # debug
                        continue
                    if callee_fn not in added_plt:
                        assert(callee_fn.is_syscalls_collected)
                        self.syscall_set.update(callee_fn.syscall_set)
                        added_plt.append(callee_fn)

    def __create_func_cfg(self, fn: Function, owner_obj: Union[PHPBin, SharedObject], obj_collection: ObjCollection) -> nx.DiGraph:
        dis = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        dis.detail = True
        orig_g = fn.transition_graph
        g = nx.DiGraph()

        block_nodes: Dict[int, BlockNode] = {} # {addr: BlockNode}
        func_nodes: Dict[int, Function] = {}   # {addr: Function}
        hook_nodes:  Dict[int, HookNode]  = {} # {addr: HookNode}

        for node in orig_g.nodes:
            if isinstance(node, BlockNode):
                if node.addr not in block_nodes:
                    block_nodes[node.addr] = node
                g.add_node(node)
            elif isinstance(node, Function):
                if node.addr not in func_nodes:
                    func_nodes[node.addr] = node
            elif isinstance(node, HookNode):
                if node.addr not in hook_nodes:
                    hook_nodes[node.addr] = node
            else:
                print(f"[_create_func_cfg]: Unknown node type {type(node)}")
                pdb.set_trace()

        # create a skeleton CFG with only BlockNode nodes
        for node in orig_g.nodes:
            if not isinstance(node, BlockNode):
                continue
            if node.addr == fn.addr:
                self.entry_nodes.append(node)
            for s in orig_g.successors(node):
                if isinstance(s, BlockNode):
                    g.add_edge(node, s)

        # below are two types of (BlockNode, Function) edges we are going to add in our CFG
        fall_through: List[Tuple[BlockNode, CallOut, BlockNode]] = [] # a fall-through edge connect a function (a Function node)'s call site (a BlockNode) with its return site (a BlockNode)
        non_returnning: List[Tuple[BlockNode, CallOut]] = [] # edges to connect a BlockNode with a non returnning function

        for node in g.nodes(): # type: ignore 
            node: BlockNode
            block_ins = [i for i in dis.disasm(node.bytestr, node.addr)]
            if len(block_ins) == 0:
                warnings.warn(f"[PHPFunction _create_func_cfg]: empty block {hex(node.addr)} in function {self.symbolic_name} CFG.")
                continue
            last_ins = block_ins[-1]
            if last_ins.mnemonic != "call":
                continue

            call_nodes =  [t for t in orig_g.successors(node) if isinstance(t, Function)]
            if len(call_nodes) > 1:
                print("[PHPFunction::_create_func_cfg]: the call instruction has more than one target")
                pdb.set_trace() # debug
                continue
            elif len(call_nodes) == 0:
                print("[PHPFunction::_create_func_cfg]: the call instruction has no target")
                # this happens when the call is from another function's code block and is incorrectly treated as the current function's code block
                continue

            call_target = call_nodes[0]
            # check if last_ins's operand is a constant number, otherwise it is an indirect call 
            operand_type = last_ins.operands[0].type
            if operand_type == capstone.x86.X86_OP_REG:
                assert(not last_ins.op_str.startswith("0x")) # debug
                op_reg = last_ins.reg_name(last_ins.operands[0].reg, "")
                call_out = CallOut(CallOutType.INDIRECT_REG) # owner_obj and symbolic_name is unknown for this type
                call_out.call_site = last_ins.address
                call_out.op_reg = op_reg if op_reg else ""
                call_out.caller_symbolic_name = self.symbolic_name
                call_out.caller_addr = self.addr
                ret_addr = last_ins.address + last_ins.size
                if ret_addr not in block_nodes:
                    print(f"[PHPFunction _create_func_cfg]: cannot find return block {hex(ret_addr)} in function {self.symbolic_name} CFG.")
                    non_returnning.append((node, call_out))
                else:
                    next_node = block_nodes[ret_addr]
                    fall_through.append((node, call_out, next_node))
                self.call_outs[call_out.call_site] = call_out
                continue
            elif operand_type == capstone.x86.X86_OP_MEM:
                call_out = CallOut(CallOutType.INDIRECT_MEM) # owner_obj and symbolic_name is unknown for this type
                call_out.call_site = last_ins.address
                call_out.op_mem = last_ins.op_str
                call_out.caller_symbolic_name = self.symbolic_name
                call_out.caller_addr = self.addr
                ret_addr = last_ins.address + last_ins.size
                if ret_addr not in block_nodes:
                    print(f"[PHPFunction _create_func_cfg]: cannot find return block {hex(ret_addr)} in function {self.symbolic_name} CFG.")
                    non_returnning.append((node, call_out))
                else:
                    next_node = block_nodes[ret_addr]
                    fall_through.append((node, call_out, next_node))
                self.call_outs[call_out.call_site] = call_out
                continue

            # direct call target or a PLT entry
            assert(operand_type == capstone.x86.X86_OP_IMM) # for debug
            call_target = int(last_ins.op_str, 16)
            func = func_nodes.get(call_target)

            if func is None:
                # if this happens, then the call is probally from another function's code block (see connected component part below)
                continue

            # here the func is a system call wrapper 
            if func.name in system_calls.syscalls().names() and self.contain_syscall == ContainSyscall.UNKNOWN:
                self.contain_syscall = ContainSyscall.DIRECT
                # syscall wrapper is also PLT

            # Check if the call target is a PLT entry and found the function's real address from its owner library
            if func.is_plt:
                call_out = CallOut(CallOutType.UNRESOLVED_PLT)
                call_out.symbolic_name = func.name
                call_out.call_site = last_ins.address
                call_out.addr = func.addr # temporily set as a plt entry addr
                call_out.caller_symbolic_name = self.symbolic_name
                call_out.caller_addr = self.addr
                call_out.process_plt_call_out(owner_obj, obj_collection)
                # for plt callout, we temporily treat the function as non-returnning
                self.call_outs[call_out.call_site] = call_out
                non_returnning.append((node, call_out))
            else:
                call_out = CallOut(CallOutType.DIRECT)
                call_out.symbolic_name = func.name
                call_out.call_site = last_ins.address
                call_out.addr = func.addr
                call_out.caller_symbolic_name = self.symbolic_name
                call_out.caller_addr = self.addr
                ret_addr = last_ins.address + last_ins.size
                self.call_outs[call_out.call_site] = call_out
                if ret_addr not in block_nodes:
                    print(f"[PHPFunction _create_func_cfg]: cannot find return block {hex(ret_addr)} in function {self.symbolic_name} CFG.")
                    non_returnning.append((node, call_out))
                else:
                    next_node = block_nodes[ret_addr]
                    if not func.returning:
                        non_returnning.append((node, call_out))
                    else:
                        fall_through.append((node, call_out, next_node))

        # Now we add the fall through edges that connect the Callout node and also handle non-returnning function's edges
        for f in fall_through:
            g.add_node(f[1])  # add the callout node
            if g.has_edge(f[0], f[2]): # original edge that link a function's callsite and return site
                g.remove_edge(f[0], f[2])
            # add new edges
            g.add_edge(f[0], f[1])
            g.add_edge(f[1], f[2])

        for n in non_returnning:
            g.add_node(n[1])
            g.add_edge(n[0], n[1])
        
        
        # sometimes the subsequent (in terms of location in ELF) function's block is treated as the current function's cfg
        # This might due to lack of proper handling padding bytes in our code or in the library
        ccs = [c for c in nx.weakly_connected_components(g)]
        if len(ccs) == 1:
            self.cfg_asyclic = nx.is_directed_acyclic_graph(g)
            return g

        for c in ccs:
            sub_graph = g.subgraph(c)
            smallest_node = min([node for node in sub_graph.nodes if not isinstance(node, CallOut)], key=lambda x: x.addr)
            if smallest_node.addr == self.addr: # keep the sub_graph that matches our initial entry address
                g = sub_graph
                break 
        self.cfg_asyclic = nx.is_directed_acyclic_graph(g) 
        return g
    
    def plot_func_orig_cfg(self):
        plot_func_graph(self.orig_fn.project, self.orig_fn.transition_graph, f"./func_cfg/{self.symbolic_name}_orig_cfg", "png", asminst=True)

    def plot_func_cfg(self):
        plot_func_graph(self.orig_fn.project, self.cfg, f"./func_cfg/{self.symbolic_name}_cfg", "png", asminst=True)
    
    def get_callouts(self, type: CallOutType):
        for callout in self.call_outs.values():
            if callout.type == type:
                yield callout

    def gen_call_sequences_from_acyclic_cfg(self):
        cfg = self.pruned_cfg
        ''' Generate call sequences from acyclic cfg '''
        # if the cfg is empty, then return empty sequences
        print(f"[PHPFunction gen_call_sequences_from_acyclic_cfg]: {self.symbolic_name}")

        if cfg is None or len(cfg.nodes) == 0:
            self.call_sequences = []
            return
        
        # a fast pass can be made if the function does not contain any syscall then we can return empty sequences
        if self.contain_syscall == ContainSyscall.NONE:
            self.call_sequences = []
            return

        sequences = []


        def dfs(node, path):
            if node in visited:
                return
            
            visited.add(node)
            path.append(node.name)
            
            for successor in cfg.successors(node):
                dfs(successor, path.copy())

            if not list(cfg.successors(node)) and len(path) > 0: # sink node 
                if path not in sequences:
                    sequences.append(path)

            visited.remove(node)


        for entry_node in self.entry_nodes:
            visited = set()
            dfs(entry_node, [])

        self.call_sequences = sequences


# def resolve_contain_syscall(func: PHPFunction, func_collection: Dict[str, PHPFunction], visited=None): 
#     if visited is None:
#         visited = set()
#     
#     if func.contain_syscall != ContainSyscall.UNKNOWN:
#         return func.contain_syscall
# 
#     for _, callee_name in func.direct_callouts.items():
#         if callee_name in visited:
#             continue
#         visited.add(callee_name)
#         if callee_name in func_collection:
#             callee = func_collection[callee_name]
# 
#             # if the callee's status is known then we can directly get the result
#             if callee.contain_syscall == ContainSyscall.DIRECT or callee.contain_syscall == ContainSyscall.INDIRECT:
#                 func.contain_syscall = ContainSyscall.INDIRECT
#                 return ContainSyscall.INDIRECT
# 
#             # if the callee's status is unkonwn then we need to resolve it recursively
#             elif callee.contain_syscall == ContainSyscall.UNKNOWN:
#                 callee_contain_syscall = resolve_contain_syscall(callee, func_collection, visited)
#                 if callee_contain_syscall == ContainSyscall.DIRECT or callee_contain_syscall == ContainSyscall.INDIRECT:
#                     func.contain_syscall = ContainSyscall.INDIRECT
#                     return ContainSyscall.INDIRECT
# 
#     # if we go through all the callees and none of them contain syscall, then this function does not contain syscall
#     func.contain_syscall = ContainSyscall.NONE
#     return ContainSyscall.NONE

def is_node_function_contain_syscall(node, func_collection: Dict[str, PHPFunction]): 
    if not isinstance(node, Function):
        return False

    if node.name in system_calls.syscalls().names():
        return True

    if node.name in func_collection:
        fn = func_collection[node.name]
        if fn.contain_syscall == ContainSyscall.DIRECT or fn.contain_syscall == ContainSyscall.INDIRECT:
            return True
        else:
            return False
    return False

def prune_cfg(php_func: PHPFunction, func_collection: Dict[str, PHPFunction]):
     # Creating a new Digraph to store only Function nodes that involves syscalls
    pruned_cfg = nx.DiGraph()
    
    func_nodes = []
    for node in php_func.cfg.nodes():
        if is_node_function_contain_syscall(node, func_collection):
            func_nodes.append(node)

    merged_predecessors = {node: set() for node in php_func.cfg.nodes()}

    def dfs(node, last_func_node, visited):
        if node in visited:
            return
        visited.add(node)
        if is_node_function_contain_syscall(node, func_collection):
            last_func_node = node
        merged_predecessors[node].add(last_func_node)
        for s in php_func.cfg.successors(node):
            dfs(s, last_func_node, visited)
    
    for u in func_nodes:
        visited = set()
        dfs(u, u, visited)
    
    for u, v in php_func.cfg.edges:
        if not is_node_function_contain_syscall(u, func_collection) and is_node_function_contain_syscall(v, func_collection):
            merged_u = merged_predecessors[u]
            merged_v = merged_predecessors[v]
            for c_u, c_v in product(merged_u, merged_v):
                pruned_cfg.add_edge(c_u, c_v)
        elif is_node_function_contain_syscall(u, func_collection) and is_node_function_contain_syscall(v, func_collection):
            pruned_cfg.add_edge(u, v)
    entry_nodes =  [node for node in pruned_cfg.nodes() if pruned_cfg.in_degree(node) == 0] # after the pruning, there can be more than one entry node
    php_func.entry_nodes = entry_nodes
    php_func.pruned_cfg = pruned_cfg
    php_func.pruned_cfg_node_num = len(pruned_cfg.nodes())

def get_call_seqs_from_fn_name(fn_name: str, func_collection: Dict[str, PHPFunction]):
    if fn_name not in func_collection:
        yield []
    else:
        for seq in func_collection[fn_name].call_sequences:
            yield seq

def expand_calls(fn_name: str, func_collection: Dict[str, PHPFunction])-> List[List[str]]:
    if fn_name in system_calls.syscalls().names():
        return [[fn_name]]
    else:
        php_func = func_collection.get(fn_name)
        if php_func:
            return gen_syscall_seqs_from_call_seqs(php_func, func_collection)
        else:
            return []

def gen_syscall_seqs_from_call_seqs(php_func: PHPFunction, func_collection: Dict[str, PHPFunction])-> List[List[str]]:
    result = []
    for call_seq in php_func.call_sequences:
        expanded_seqs = [[]]
        for fn_name in call_seq:
            current_expansion = expand_calls(fn_name, func_collection)
            expanded_seqs = [seq1 + seq2 for seq1 in expanded_seqs for seq2 in current_expansion]
        result.extend(expanded_seqs)
    return result

def produce_syscall_seqs_for_func(func_name: str, func_collection: Dict[str, PHPFunction])-> List[List[str]]:
    if func_name not in func_collection:
        print("undefined function in the collection")
        return []
    
    fn = func_collection[func_name]

    if len(fn.pruned_cfg.nodes) > 30:
        print("too much node")
        return []
    
    if not fn.cfg_asyclic:
        print("cycle cfg")
        return []

    fn.gen_call_sequences_from_acyclic_cfg()
    
    if len(fn.call_sequences) == 0:
        return []

    sys_seqs = gen_syscall_seqs_from_call_seqs(fn, func_collection)
    if len(sys_seqs) == 0:
        return []
    
    return sys_seqs

class ExternFunction:
    def __init__(self,func_sym: Symbol, owner_obj: SharedObject) -> None:
        self.func_sym = func_sym
        self.owner_obj = owner_obj
        self.symbolic_name = func_sym.name

