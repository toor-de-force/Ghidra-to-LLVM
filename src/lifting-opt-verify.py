import llvmlite.binding as llvm


def optimize(module, level):
    llvm.initialize()
    llvm.initialize_native_target()
    llvm.initialize_native_asmprinter()
    module_ref = llvm.parse_assembly(str(module))
    if level is None:
        return module_ref
    pmb = llvm.create_pass_manager_builder()
    pm = llvm.create_module_pass_manager()
    pmb.opt_level = level
    pmb.populate(pm)
    pm.run(module_ref)
    return module_ref


def verify(module):
    module_bc = llvm.parse_bitcode(module.as_bitcode())
    module_bc.verify()
    return module_bc


def graph(module):
    module_ref = llvm.parse_assembly(str(module))
    functions = module_ref.functions
    images = []
    for func in functions:
        cfg = llvm.get_function_cfg(func)
        graph = llvm.view_dot_graph(cfg, view=False)
        image = graph.render(format='png', directory="graphs")
        images.append(image)
    return images