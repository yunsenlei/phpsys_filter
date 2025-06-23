import re
import pdb
from ast_node import AstNode, CallAstNode
from typing import List, Dict, Tuple
from specs import Indent
from specs import ast_node_specs

class PhpBasicBlock:
    def __init__(self, block_dict: Dict):
        self.id = block_dict['_gvid']
        self.name = block_dict['name']
        self.viz_text = "ID:" + str(self.id) + "\n" + block_dict['label']         
        self.contain_call_node = False
        self.ast_nodes = []

    @classmethod
    def from_dict(cls, bb_dict: Dict):
        if 'label' not in bb_dict:
            raise ValueError("BasicBlockParser: no label in the basic block dict")

        ast_str = bb_dict['label']
        ast_node_list, contain_call_node = cls._parse_ast_nodes(ast_str)
        bb = cls(bb_dict)
        bb.ast_nodes = ast_node_list
        bb.contain_call_node = contain_call_node
        return bb

    def get_ast_nodes(self):
        for node in self.ast_nodes:
            yield node

    def create_call_nodes_from_block(self):
        for node in self.ast_nodes: 
            if node.type == "Expr_FuncCall":
                yield CallAstNode(node.type, node.attrs)
            elif node.type == "Expr_MethodCall":
                yield CallAstNode(node.type, node.attrs)
            elif node.type == "Expr_StaticCall":
                yield CallAstNode(node.type, node.attrs)
            elif node.type == "Expr_NsFuncCall":
                yield CallAstNode(node.type, node.attrs)

    @classmethod
    def _parse_ast_nodes(cls, label_str: str) -> Tuple[List[AstNode], bool]:
        label_str = label_str.lstrip("\\l")
        parts = label_str.split("\\l")
        parsed_nodes = []
        header = ""
        expected_attrs = []
        i = 0
        contain_call_node = False
        while i < len(parts):
            tmp_str = parts[i]
            if  cls._is_header_str(tmp_str):
                header = cls._get_header(tmp_str[Indent.HDR_INDENT.value:].strip())

                # A phi node is an instruction used to select a value depending on the predecessor of the current blockwe
                # we don't need for our purpose, therefore skip it
                if re.match(r'Var#(\d+)(<.*>)? = Phi\(.*\)', header):
                    parsed_nodes.append(AstNode(header, {}))
                    i += 1
                    continue

                # check if it's a valid header in our specification, if not skip to the next header
                if header not in ast_node_specs:
                    print(f"header {header} not in ast_node_specs, skip to the next header")
                    while i < len(parts):
                        i += 1
                        tmp_str = parts[i]
                        if cls._is_header_str(tmp_str):
                            break
                    continue # need to skip the rest of the loop that parses the attributes
                
                # A valid header is read, now we start to parse its attributes
                if AstNode.is_call_node(header) and not contain_call_node:
                    contain_call_node = True

                expected_attrs = ast_node_specs[header]
                if len(expected_attrs) == 0:
                    parsed_nodes.append(AstNode(header, {}))
                    i += 1
                else:
                    i, node_attrs = cls._parse_attrs(i + 1, parts, expected_attrs) # i updated within the parse_attrs
                    parsed_nodes.append(AstNode(header, node_attrs)) 
            else: # we only start parsing at the begining of a header
                i += 1

        return parsed_nodes, contain_call_node

    @classmethod
    def _parse_attrs(cls, i: int, parts: List, expected_attrs: List):
        attr_key = ""
        attr_val = ""
        attr_dict = {}
        while i < len(parts):
            tmp_str = parts[i]
            if tmp_str.startswith(" " * Indent.ATTR_INDENT.value):
                attr_kv = tmp_str[Indent.ATTR_INDENT.value:]
                attr_key, key_num = cls._get_key_from_pair_str(attr_kv, expected_attrs)
                if attr_key != "" and key_num == "": # a standard key: value is parsed
                    attr_val = attr_kv[len(f"{attr_key}: "):]
                    attr_dict[attr_key] = attr_val
                elif attr_key != "" and key_num != "": # a key[num]: value is parsed
                    attr_val = attr_kv[len(f"{attr_key}[{key_num}]: "):]
                    if attr_key not in attr_dict:
                        attr_dict[attr_key] = []
                    attr_dict[attr_key].append(attr_val)
                elif attr_key == "" and key_num == "": # not a key value pair, but a continuation of the previous value
                    last_key = list(attr_dict.keys())[-1]
                    if isinstance(attr_dict[last_key], list):
                        attr_dict[last_key][-1] += attr_kv
                    else:
                        attr_dict[last_key] += attr_kv 
            elif cls._is_header_str(tmp_str):
                break
            i += 1 # continue the loop until the next header 
        return i, attr_dict

    @staticmethod
    def _get_key_from_pair_str(s: str, expected_keys: List) -> Tuple[str, str]:
        for e_k in expected_keys:
            # sometimes it is a standard key:val, other times the key contains a number, e.g. arg[0]:val
            pattern = r'^{}(?:\[(\d+)\])?: (.*)$'.format(e_k)
            m = re.match(pattern, s)
            if m:
                num = m.group(1) if m.group(1) else ""
                return e_k, num
        return "", ""

    @staticmethod
    def _get_header(header: str):
        if header.startswith("Stmt_ClassMethod"):
            return "Stmt_ClassMethod"
        elif header.startswith("Expr_Assertion"):
            return "Expr_Assertion"
        elif header.startswith("Expr_Closure"):
            return "Expr_Closure"
        elif header.startswith("Stmt_Function"):
            return "Stmt_Function"
        return header

    @staticmethod
    def _is_header_str(s: str)-> bool:
        return s.startswith(" " * Indent.HDR_INDENT.value) and not s.startswith(" " * Indent.ATTR_INDENT.value)

