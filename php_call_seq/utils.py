from itertools import islice
from typing import List, Tuple
import re
from enum import Enum

class BlockType(Enum):
    BLOCK = 1
    HEADER = 2
    UNKNOWN = 3
 
def parse_block_name(s: str) -> Tuple[BlockType, int]:
    block_pattern = r"func_(\d+)_block_(\d+)"
    header_pattern = r"func_(\d+)_header"
    match_block = re.match(block_pattern, s)
    match_header = re.match(header_pattern, s)
    if match_block:
        func_id = int(match_block.group(1), 10)
        return BlockType.BLOCK, func_id 
    elif match_header:
        func_id = int(match_header.group(1), 10)
        return BlockType.HEADER, func_id
    return BlockType.UNKNOWN, -1


def parse_function_name(s: str):
    if s == "Function {main}():":
        return "", "main"

    pattern = r"Function (([a-zA-Z_\x7f-\xff][a-zA-Z0-9_\x7f-\xff]*)::)?([a-zA-Z_\x7f-\xff][a-zA-Z0-9_\x7f-\xff]*)\(\):"
    match = re.match(pattern, s)
    if match:
        class_name = match.group(2) if match.group(2) else ""
        func_name = match.group(3)
    else:
        class_name = ""
        func_name = ""
    return class_name, func_name
        
def is_literal(s: str):
    pattern = r"LITERAL\((\\'(.*?)\\')|(\d+)\)"
    match = re.search(pattern, s)
    if match:
        return True, match.group(2)
    else:
        return False, ""

def get_str_literal(s: str):
    pattern = r"LITERAL\(\\'(.*?)\\'\)"
    match = re.search(pattern, s)
    if match:
        return match.group(1)
    else:
        return ""


def is_named_var(s: str):
    match = re.match(r"Var#(\d+)<\$([a-zA-Z_][a-zA-Z0-9_]*)>", s)
    if match:
        return True
    else:
        return False
    
def get_var_id_from_str(s: str):
    match = re.match(r"Var#(\d+)<\$([a-zA-Z_][a-zA-Z0-9_]*)>", s)
    if match:
        return int(match.group(1), 10)
    else:
        return -1

