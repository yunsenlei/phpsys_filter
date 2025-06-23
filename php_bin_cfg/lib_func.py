
# This is a representation of library functions used by the PHP binary
# It is not foundamentally different from the PHPFunction class, and we contruct their CFGs in the same way
# TOTO: fugure work could build the cfg construction as a factory pattern
from os import sysconf_names
import pdb
from angr import project
import networkx as nx
import capstone
import claripy
from capstone import CsInsn
from typing import Dict, List, Tuple, Set
from cle import Symbol
from angr import Project
from angr.knowledge_plugins.functions.function import Function
from angr.codenode import BlockNode, HookNode
from angrutils import plot_func_graph
from shared_object import SharedObject, ObjCollection
from callout import CallOut, CallOutType

class LibFunction:
    def __init__(self, fn: Function, owner_obj: SharedObject, obj_collection: ObjCollection):
        self.orig_fn = fn
        self.symbolic_name = fn.name
        self.owner_obj_name = owner_obj.name
        self.addr = fn.addr
        self.is_syscalls_collected = False
        self.call_outs: Dict[int, CallOut] = {} # call_site: CallOut
        self.syscall_set: Set[int] = set()
        self.cfg: nx.DiGraph = self._create_func_cfg(owner_obj, obj_collection) 
        self._get_syscall_set()
        # ignofre indirect callout for now
        if len(list(self.get_callouts(CallOutType.DIRECT))) == 0 and len(list(self.get_callouts(CallOutType.RESOLVED_PLT))) == 0:
            self.is_syscalls_collected = True
    
    def __eq__(self, other):
        if not isinstance(other, LibFunction):
            return False
        return self.addr == other.addr and self.owner_obj_name == other.owner_obj_name
    
    def __hash__(self):
        # when a LibFunction is created from a callout: self.addr = callout.addr and self.owner_obj_name == callout.owner_obj_name
        # this is how we can find the LibFunction from a CallOut (only DIRECT and RESOLVED_PLT), indirect callout need to be resolved first
        return hash((self.addr, self.owner_obj_name))


    @classmethod
    def from_callout(cls, callout: CallOut, obj_collection: ObjCollection):
        assert(callout.type == CallOutType.RESOLVED_PLT or callout.type == CallOutType.DIRECT)
        owner_obj = obj_collection.get_owner_obj(callout.owner_obj_name)
        if owner_obj is None:
            print(f"[from_callout]: cannot find owner obj for {callout.owner_obj_name}")
            pdb.set_trace()
            return
        assert(owner_obj.name == callout.owner_obj_name)
        if owner_obj.cfg is None:
            owner_obj.cfg = owner_obj.load_or_create_cfg()
        fn = owner_obj.cfg.functions.get_by_addr(callout.addr)
        if fn is None:
            print(f"[from_callout]: cannot find function {callout.symbolic_name} at addr {hex(callout.addr)}")
            pdb.set_trace()
            return
        assert(callout.addr == fn.addr)
        lib_fn = LibFunction(fn, owner_obj, obj_collection)
        return lib_fn

    def get_callouts(self, type: CallOutType):
        for callout in self.call_outs.values():
            if callout.type == type:
                yield callout

    # unlike _get_syscall_set, this function collect all syscall set from its callees
    def collect_all_syscall_sets(self, lib_funcs: Dict[int, "LibFunction"]):
        all_syscalls = set()
        visited_fn: Set[LibFunction] = set() # if a callee function appears more than once, it does not contribute to new syscall
        resolve_stack: List[LibFunction] = [self]

        while len(resolve_stack) > 0:
            current_fn = resolve_stack.pop()
            if current_fn in visited_fn:
                continue

            visited_fn.add(current_fn)
            all_syscalls.update(current_fn.syscall_set) # initialize to direct system calls used in the current function

            if current_fn.is_syscalls_collected: # the syscall set added is already final for the function, therefore no need to process any callee
                continue

            for callout in current_fn.call_outs.values():
                if callout.type != CallOutType.RESOLVED_PLT and callout.type != CallOutType.DIRECT:
                    continue
                libfunc_hash = hash((callout.addr, callout.owner_obj_name))
                if libfunc_hash not in lib_funcs:
                    print(f"[collect_all_syscall_sets]: cannot find a LibFunction callee {callout.symbolic_name} from a CallOut object")
                    pdb.set_trace()
                    continue
                callee_func = lib_funcs[libfunc_hash]
                assert(callee_func.addr == callout.addr and callee_func.owner_obj_name == callout.owner_obj_name)
                if callee_func not in visited_fn:
                    resolve_stack.append(callee_func)

        self.syscall_set = all_syscalls
        self.is_syscalls_collected = True

    def _create_func_cfg(self, owner_obj, obj_collection)->nx.DiGraph:

        dis = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        dis.detail = True

        orig_g = self.orig_fn.transition_graph
        g = nx.DiGraph()
        
        block_nodes: Dict[int, BlockNode] = {}
        func_nodes:  Dict[int, Function]  = {}
        hook_nodes:  Dict[int, HookNode]  = {}
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
        
        for node in orig_g.nodes:
            if not isinstance(node, BlockNode):
                continue
            for s in orig_g.successors(node):
                if isinstance(s, BlockNode):
                    g.add_edge(node, s) # node and s has already been added to g

        # now we have a graph g with only block nodes and edges between them
        fall_through: List[Tuple[BlockNode, CallOut, BlockNode]] = [] 
        non_returnning: List[Tuple[BlockNode, CallOut]] = []
        for node in g.nodes():
            if not isinstance(node, BlockNode):
                continue
            
            block_ins = [i for i in dis.disasm(node.bytestr, node.addr)] 
            if len(block_ins) == 0:
                print(f"[_create_func_cfg]: empty block {hex(node.addr)} in function {self.symbolic_name} CFG.")
                continue
            last_ins = block_ins[-1]
            if last_ins.mnemonic != "call":
                continue

            call_nodes =  [t for t in orig_g.successors(node) if isinstance(t, Function)]
            if len(call_nodes) != 1:
                print("[_create_func_cfg]:a call instruction has no call target")
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
                # for INDIRECT_REG, call_out.addr and call_out.owner_obj_name is unknown at this point
                ret_addr = last_ins.address + last_ins.size
                if ret_addr not in block_nodes:
                    print(f"[_create_func_cfg]: cannot find return block {hex(ret_addr)} in function {self.symbolic_name} CFG.")
                    pdb.set_trace()
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
                # for INDIRECT_MEM, call_out.addr and call_out.owner_obj_name is unknown at this point
                ret_addr = last_ins.address + last_ins.size
                if ret_addr not in block_nodes:
                    print(f"[_create_func_cfg]: cannot find return block {hex(ret_addr)} in function {self.symbolic_name} CFG.")
                    pdb.set_trace()
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
                continue

            if func.is_plt:
                call_out = CallOut(CallOutType.UNRESOLVED_PLT)
                call_out.symbolic_name = func.name
                call_out.call_site = last_ins.address
                call_out.addr = func.addr # temporily set as a plt entry addr
                call_out.process_plt_call_out(owner_obj, obj_collection)
                self.call_outs[call_out.call_site] = call_out
                # for plt callout, we temporily treat the function as non-returnning
                non_returnning.append((node, call_out))
            else:
                call_out = CallOut(CallOutType.DIRECT)
                call_out.symbolic_name = func.name
                call_out.call_site = last_ins.address
                call_out.addr = func.addr
                call_out.owner_obj_name = owner_obj.name
                ret_addr = last_ins.address + last_ins.size
                self.call_outs[call_out.call_site] = call_out
                if ret_addr not in block_nodes:
                    non_returnning.append((node, call_out))
                else:
                    next_node = block_nodes[ret_addr]
                    if not func.returning:
                        non_returnning.append((node, call_out))
                    else:
                        fall_through.append((node, call_out, next_node))

        # Now we add the fall through edge and non-returnning edge
        for f in fall_through:
            g.add_node(f[1])  # add the callout node
            if g.has_edge(f[0], f[2]): # original edge that link a function's callsite and return site
                g.remove_edge(f[0], f[2])
            g.add_edge(f[0], f[1]) # call site to callout node
            g.add_edge(f[1], f[2]) # callout node to return site

        for n in non_returnning:
            g.add_node(n[1])
            g.add_edge(n[0], n[1])

        # sometimes the subsequent function's block is treated as current function's cfg (padding not handled correctly?)
        ccs = [c for c in nx.weakly_connected_components(g)]
        if len(ccs) == 1:
            return g

        # keep the sub_graph that matches our initial entry address
        for c in ccs:
            sub_graph = g.subgraph(c)
            smallest_node = min([node for node in sub_graph.nodes if not isinstance(node, CallOut)], key=lambda x: x.addr)
            if smallest_node.addr == self.addr: 
                g = sub_graph
                break 
        return g


    # get syscalls directly called by this function
    def _get_syscall_set(self):
        dis = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        dis.detail = True
        for node in self.cfg.nodes:
            if not isinstance(node, BlockNode):
                continue
            block_ins = [i for i in dis.disasm(node.bytestr, node.addr)] 
            if len(block_ins) == 0:
                print(f"[_create_func_cfg]: empty block {hex(node.addr)} in function {self.symbolic_name} CFG.")
                continue
            last_ins = block_ins[-1]

            if last_ins.mnemonic == "syscall":
                sys_nums = self.get_syscall_num_from_block(node, block_ins)
                self.syscall_set.update(sys_nums)

    def get_syscall_num_from_block(self, bn: BlockNode, block_ins: List[CsInsn]) -> Set[int]:
        print(f"[get_syscall_num_from_block]: resolving syscall number at {hex(block_ins[-1].address)}")

        # a hard-coded fast path to get syscall from a syscall instruction's previous mov instruction
        if len(block_ins) >= 2 and block_ins[-1].mnemonic == "syscall" and block_ins[-2].mnemonic == "mov": 
            mov_ins = block_ins[-2]
            ops = block_ins[-2].operands
            op_reg = mov_ins.reg_name(ops[0].reg) 
            sys_num = ops[1]
            if op_reg == "eax" and sys_num.type == capstone.x86.X86_OP_IMM:
                return set([sys_num.imm])
        
        # using angr's simulation to get value of eax
        syscall_ins_addr = block_ins[-1].address
        fn_proj = self.orig_fn.project
        if fn_proj is None:
            print("[get_syscall_num_from_block]: function project is None")
            pdb.set_trace() # debug
            return set([])

        # determine where we want the solver to begin 
        prev_blocks = self.cfg.predecessors(bn)
        sys_nums = set() 
        if len(block_ins) == 1: # in this case, the eax can only be leanred from the previous block 
            for prev_block in prev_blocks:
                if not isinstance(prev_block, BlockNode):
                    continue
                num = self._find_from_state(fn_proj, prev_block.addr, syscall_ins_addr)
                if num != -1:
                    sys_nums.add(num)
        else:
            num = self._find_from_state(fn_proj, block_ins[0].address, syscall_ins_addr)
            if num != -1: 
                sys_nums.add(num)
        return sys_nums

    def _find_from_state(self, proj: Project, start_addr: int, find_addr: int) -> int:
        state = proj.factory.blank_state(addr=start_addr)
        eax = claripy.BVS("eax", 32)
        state.add_constraints(eax == -1)
        state.regs.eax = eax
        simgr = proj.factory.simulation_manager(state)
        simgr.explore(find=find_addr)

        if 'found' not in simgr.stashes:
            print("[get_syscall_num_from_block]: solver cannot resolve eax for syscall instruction")
            return -1

        if len(simgr.stashes['found']) < 1: 
            print(f"[get_syscall_num_from_block]: solver cannot resolve syscall instructions")
            return -1

        found_state = simgr.stashes['found'][0] # the find above is a single address so we only have one state
        sys_num = found_state.solver.eval(found_state.regs.eax) # type: ignore
        print(f"[_find_from_state]: found eax value {sys_num} at {hex(find_addr)}")
        return sys_num


    def plot_func_orig_cfg(self):
        plot_func_graph(self.orig_fn.project, self.orig_fn.transition_graph, f"./func_cfg/{self.symbolic_name}_orig_cfg", "png", asminst=True)

    def plot_func_cfg(self):
        plot_func_graph(self.orig_fn.project, self.cfg, f"./func_cfg/{self.symbolic_name}_cfg", "png", asminst=True)
