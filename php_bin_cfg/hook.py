import angr
from angr.sim_procedure import SimProcedure


class IndirectCallHook(SimProcedure):
    def __init__(self, register, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.register = register

    def run(self):
        reg = getattr(self.state.regs, self.register)
        target_addr = self.state.solver.eval(reg)
        print(f"Indirect call to", target_addr)


