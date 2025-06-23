import os
import enum
import capstone
import pdb
from shared_object import ObjCollection

class CallOutType(enum.Enum):
    UNKNOWN = 0
    DIRECT = 1
    INDIRECT_REG = 2
    INDIRECT_MEM = 3
    UNRESOLVED_PLT = 4
    RESOLVED_PLT = 5

class CallOut:
    def __init__(self, type) -> None:
        self.type: CallOutType = type
        self.owner_obj_name: str = ""
        self.call_site: int = 0
        self.addr: int = 0

        self.caller_symbolic_name: str = ""
        self.caller_addr: int = 0

        self.symbolic_name: str = ""
        self.symbolic_name2: str = "" # for PLT: name in the target object might be different from the name when it's called

        self.op_reg: str = "" # for indirect calls with register as target
        self.op_mem: str = "" # for indirect calls with indirect memory location as target

    def __eq__(self, other):
        if not isinstance(other, CallOut):
            return False
        # two callout are the same if they refers to the same function
        return self.type == other.type \
        and self.owner_obj_name == other.owner_obj_name \
        and self.addr == other.addr

    def __hash__(self):
        return hash((self.type, self.addr, self.owner_obj_name))

    def process_plt_call_out(self, caller_obj, obj_collection: ObjCollection):
        dis = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        dis.detail = True

        # follow the PLT entry to the GOT entry first
        plt_entry = caller_obj.proj.loader.memory.load(self.addr, 0x10)
        plt_entry_ins = [i for i in dis.disasm(plt_entry, self.addr)]
        
        # two types of plt entries
        if plt_entry_ins[0].mnemonic == "endbr64" and plt_entry_ins[1].mnemonic == "bnd jmp":
            jmp_ins = plt_entry_ins[1]
            relative_addr = jmp_ins.operands[0].mem.disp # should be scale * index + disp, but I think the first part is 0
            nxt_ins_addr = plt_entry_ins[2].address
            got_entry_addr = nxt_ins_addr + relative_addr # assume relative PC addressing
        elif plt_entry_ins[0].mnemonic == "jmp":
            jmp_ins = plt_entry_ins[0]
            relative_addr = jmp_ins.operands[0].mem.disp 
            nxt_ins_addr = plt_entry_ins[1].address
            got_entry_addr = nxt_ins_addr + relative_addr # assume relative PC addressing
        else:
            print(f"[process_plt_call_out]: PLT entry {hex(self.addr)} cannot be parsed")
            self.type = CallOutType.UNRESOLVED_PLT
            pdb.set_trace() # debug
            return
        
        base_addr = caller_obj.proj.loader.main_object.mapped_base
        find_reloc = got_entry_addr - base_addr
        matched_reloc = caller_obj.relocs.get(find_reloc)
        
        if matched_reloc is None:
            print(f"[process_plt_call_out]: Cannot find matched relocation entry for PLT entry {hex(self.addr)}")
            self.type = CallOutType.UNRESOLVED_PLT
            pdb.set_trace() # debug
            return     

        if matched_reloc.resolvedby is None:
            print(f"[process_plt_call_out]: Cannot find symbol for relocation entry for PLT entry {hex(self.addr)}")
            self.type = CallOutType.UNRESOLVED_PLT
            pdb.set_trace() # debug
            return

        # the library api does the heavy lifting for us, so we don't actually need to follow the .rela.plt and .dynsym
        # the symbol information is associated with the relocation entry if it's considered resolved
        plt_owner_name = os.path.basename(matched_reloc.resolvedby.owner.binary).rpartition('.so')[0] 
        plt_owner_obj = obj_collection.get_owner_obj(plt_owner_name)

        if plt_owner_obj is None:
            print(f"[process_plt_call_out]: Cannot found {plt_owner_name} in shared library list")
            self.type = CallOutType.UNRESOLVED_PLT
            return
        
        assert(plt_owner_obj.bin_path == matched_reloc.resolvedby.owner.binary) # debug

        # the shared object when creating its cfg is based on a different addresses from when it's linked by the main binary
        real_addr = matched_reloc.value - matched_reloc.resolvedby.owner.mapped_base + plt_owner_obj.proj.loader.main_object.mapped_base 
        self.addr = real_addr
        self.owner_obj_name = plt_owner_name
        self.type = CallOutType.RESOLVED_PLT
        return        
