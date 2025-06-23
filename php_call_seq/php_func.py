import pdb
import re
import networkx as nx
import graphviz as gv
from typing import Dict, List, Tuple
from specs import call_statistic
from basic_block import PhpBasicBlock
from ast_node import AstNode, CallAstNode
from utils import is_literal
from os import cpu_count
from concurrent.futures import ProcessPoolExecutor
from itertools import chain, islice
from variable import Variable, VariableScope

def chunks(data: List, size: int):
    it = iter(data)
    for _ in range(0, len(data), size):
        yield list(islice(it, size))


class PhpFunction:
    def __init__(self):
        call_statistic.total_func += 1
        self.class_name = ""
        self.func_name = ""
        self.header_block_id = -1
        self.basic_blocks : Dict[int, PhpBasicBlock] = {}
        self.call_graph_nodes: Dict[int, List[CallAstNode]] = {} # each node in call graph is a group of calls within a basic block
        self.exprs: Dict[int, AstNode] = {} # expression's id to self AST node
        self.named_local_vars: Dict[int, Variable]  = {}
        self.global_vars: Dict[str, Variable] = {}
        self.edges: List[Tuple[int, int, str]] = []
        self.cfg = nx.DiGraph()
        self.total_call_nodes = 0
        self.resolved_call_nodes = 0

    def is_edge_belong_to_function(self, edge: Tuple[int, int]) -> bool:
        return edge[0] in self.basic_blocks and edge[1] in self.basic_blocks

    def create_cfg(self):
        for id, _ in self.basic_blocks.items():
            self.cfg.add_node(id)
        for e in self.edges:
            self.cfg.add_edge(e[0], e[1])
    
    # not really a call graph, each basic block's AST node is filtered to only contain call node
    def create_call_graph_from_cfg(self):
        cfg = self.cfg
        for block_id in cfg.nodes:
            bb = self.basic_blocks[block_id]
            self.call_graph_nodes[block_id] = list(bb.create_call_nodes_from_block())
        # edges in call graph are the same as edges in cfg

    def view_graph(self):
        viz_g = gv.Digraph()
        for id, b in self.basic_blocks.items():
            viz_g.node(str(id), b.viz_text)
        for e in self.edges:
            viz_g.edge(str(e[0]), str(e[1]), e[2])
        viz_g.view("./func_graph", cleanup=True, quiet=True)

    def get_all_ast_nodes(self):
        for b in self.basic_blocks.values():
            yield from b.get_ast_nodes()

    def get_all_call_nodes(self):
        for calls in self.call_graph_nodes.values():
            yield from calls

    def get_entry_block(self):
        # return the block with the smallest id
        return self.basic_blocks[min(self.basic_blocks.keys())]

    def add_named_local_var(self, var: Variable):
        id = var.var_id
        if id not in self.named_local_vars:
            self.named_local_vars[id] = var
        else:
            print(f"duplicate var definition: {var}")

    # create a mappiong between each expression node's id to the AST node
    def create_exprs(self):
        for a in list(self.get_all_ast_nodes()):
            if 'result' not in a.attrs:
                continue
            
            literal, _ = is_literal(a.attrs['result'])
            if literal:
                continue

            match = re.match(r"Var#(\d+)", a.attrs['result']) 
            if not match:
                print(f"failed to match variable id for the expression {a.attrs}")
                continue
 
            expr_id = int(match.group(1), 10)
            self.exprs[expr_id] = a

            # need to handle assign node e.g Var#n<$a> = ....., latter assign can refers to $a Var#m<$b> = Var#n<$a>
            if a.type != "Expr_Assign" and not a.is_valid_assign_node():
                continue
            var_match = re.match(r"Var#(\d+)(<\$([a-zA-Z_][a-zA-Z0-9_]*)>)?", a.attrs['var'])
            if not var_match:
                print(f"[create_var_defs]: cannot parse attribute var from {a.attrs} in function {self.func_name}")
                continue
            var_id = int(var_match.group(1), 10)
            self.exprs[var_id] = a


    # this function scan AST nodes within a function and look for named variable definition. We exclude:
    # iterater variable 
    # variable whose value is a string, number literal, or a constant(Expr_ConstFetch)
    def create_var_defs(self):
        ast_nodes: List[AstNode] = list(self.get_all_ast_nodes())
        for a in ast_nodes:
            if a.type != "Expr_Assign":
                continue

            # parse the left side of the assignment
            if 'var' not in a.attrs:
                print(f"[create_var_defs]: Expr_Assign node has no var attribute: {a} in function {self.func_name}")
                continue
            var_match = re.match(r"Var#(\d+)(<\$([a-zA-Z_][a-zA-Z0-9_]*)>)?", a.attrs['var'])
            if not var_match:
                print(f"[create_var_defs]: cannot parse attribute var from {a.attrs} in function {self.func_name}")
                continue # the var part could be referring to another Var#id, which means it's not a named variable
            if var_match.group(2) != None:
                var = Variable.from_id_name_str(a.attrs['var'])
                if var is None:
                    print(f"[create_var_defs]: cannot parse attribute var from {a.attrs} in function {self.func_name}")
                    continue
            else:
                continue # skip the variable that is not named or the name is another expression


            # parse the right side of the assignment
            if 'expr' not in a.attrs:
                print(f"[create_var_defs]: Expr_Assign node has no expr attribute: {a} in function {self.func_name}")
                continue

            expr_literal, _ = is_literal(a.attrs['expr'])
            # we don't care if the right side is a literal, we only match if the right side is referring to another expr
            if expr_literal:
                continue
            
            if a.attrs['expr'] == "this<$this>": # 'this' is lcal variable
                var.def_by = 0
                var.class_name = self.class_name
                self.add_named_local_var(var)
                continue

            expr_match = re.match(r"Var#(\d+)(<\$([a-zA-Z_][a-zA-Z0-9_]*)>)?", a.attrs['expr']) 
            if not expr_match:
                print(f"[create_var_defs]: cannot parse expr (literal? {expr_literal}) from {a.attrs} in function {self.func_name}")
                continue
            expr_id = int(expr_match.group(1), 10)

            var.def_by = expr_id # therefore, var is defined through an expr with id expr_id
            if expr_id in self.exprs and self.exprs[expr_id]:
                def_expr = self.exprs[expr_id]
                if def_expr.type == "Iterator_Value": # skip iterater variable: e.g. foreach ($arr as $val), $val is an iterator variable
                    continue
                elif def_expr.type == "Expr_ConstFetch": # skip constant variable: e.g. $a = true, $a is a constant variable
                    continue
            else:
                print(f"[create_var_defs]: cannot find expr with id {expr_id}({type(expr_id)}) in function {self.func_name}")
                continue

            if var.var_name in self.global_vars:
                self.global_vars[var.var_name].var_scope = VariableScope.GLOBAL
                self.global_vars[var.var_name].class_name = def_expr.get_class_name_from_expr()
                continue

            self.add_named_local_var(var)

    # look for global $var to get all referenced global variable in the function
    def create_global_vars(self):
        ast_nodes = list(self.get_all_ast_nodes())
        for a in ast_nodes:
            if a.type != "Terminal_GlobalVar":
                continue
            if 'var' not in a.attrs:
                print(f"[create_global_vars]: cannot parse var attribute in {a.attrs}")
                continue
            is_var_literal, var_name = is_literal(a.attrs['var'])
            if not is_var_literal:
                print(f"[create_global_var]: global variable'name is not literal {a.attrs}")
            self.global_vars[var_name] = Variable.from_literal(a.attrs['var'])
            self.global_vars[var_name].var_scope = VariableScope.GLOBAL

    def get_all_cycles(self):
        cycles = list(nx.simple_cycles(self.cfg))
        rotated_cycles = []
        for cycle in cycles:
            min_id = min(cycle)
            min_id_index = cycle.index(min_id)
            rotated_cycle = cycle[min_id_index:] + cycle[:min_id_index]
            rotated_cycles.append(rotated_cycle)
        return rotated_cycles

    # def get_call_sequences_from_cfg(self):
    #     raw_paths = self.__extract_paths()
    #     if len(raw_paths) == 0:
    #         return []
    #     # some basic blocks within a path does not contain any call node, we can remove them
    #     nproc = cpu_count() or 4
    #     if len(raw_paths) < nproc:
    #         nproc = 1
    #     path_chunks = list(chunks(raw_paths, len(raw_paths) // nproc))
    #     with ProcessPoolExecutor() as executor:
    #         filtered_chunks = list(executor.map(self.filter_non_call_blocks, path_chunks))
    #     # re-assemble the chunks and remove duplicate path 
    #     paths = list(chain.from_iterable(filtered_chunks))
    #     paths = [list(p) for p in set(tuple(p) for p in paths)]
    #     if len(paths) == 0:
    #         return []
    #     
    #     # generate call sequences from paths
    #     if len(paths) < nproc:
    #         nproc = 1
    #     path_chunks = list(chunks(paths, len(paths) // nproc))
    #     with ProcessPoolExecutor() as executor:
    #         call_seq_chunks = list(executor.map(self.gen_call_seqs, path_chunks))
    #     call_seqs = list(chain.from_iterable(call_seq_chunks))
    #     call_seqs = [list(s) for s in set(tuple(s) for s in call_seqs)]
    #     return call_seqs
     
    def filter_non_call_blocks(self, path_chunks: List[List[int]]) -> List[List[int]]:
        filtered_path_chunks = []
        for path in path_chunks:
            tmp_p = [node_id for node_id in path if self.basic_blocks[node_id].contain_call_node]
            if len(tmp_p) > 0:
                filtered_path_chunks.append(tmp_p)
        return filtered_path_chunks

    # def gen_call_seqs(self, path_chunks: List[List[int]]):
    #     call_seqs = []
    #     for path in path_chunks:
    #         seq = []
    #         for node_id in path: 
    #             seq.extend(self.basic_blocks[node_id].get_call_nodes_from_block())
    #         call_seqs.append(seq)
    #     return call_seqs

    def __extract_paths(self)-> List[List[int]]:
        """
        Extract all paths in a function's CFG using DFS, and return a list of paths.
        Note that this function does not handle loop in the CFG.
        """
        paths = []
        entry_block = self.get_entry_block()

        # check if the entry block is the only block in the CFG
        if len(list(self.cfg.successors(entry_block.id))) == 0:
            return [[entry_block.id]]

        stack = [(entry_block.id, [entry_block.id])]
        while stack:
            (vertex, path) = stack.pop()
            for nxt in set(self.cfg.successors(vertex)) - set(path):
                if len(list(self.cfg.successors(nxt))) == 0: # sink node
                    paths.append(path + [nxt])
                else:
                    stack.append((nxt, path + [nxt]))
        return paths

    def is_func_contains_loop(self):
        if nx.is_directed_acyclic_graph(self.cfg):
            return False
        else:
            return True
