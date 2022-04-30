import angr #the main framework
import claripy #the solver engine

sym_arg_size = 30 #Length in Bytes because we will multiply with 8 later
sym_arg = claripy.BVS('sym_arg', 8*sym_arg_size)

proj = angr.Project("./target")
argv = [proj.filename]
argv.append(sym_arg)
state = proj.factory.entry_state(args=argv)

simgr = proj.factory.simulation_manager(state)

find_addr = 0x401060
simgr.explore(find=find_addr)

found = simgr.found[0] # A state that reached the find condition from explore
print(found.solver.eval(sym_arg, cast_to=bytes)) # Return a concrete string value for the sym arg to reach this state