#!/usr/bin/python3
import os
from llvmlite import ir
import xml.etree.ElementTree as et

int32 = ir.IntType(32)
int64 = ir.IntType(64)
int1 = ir.IntType(1)
void_type = ir.VoidType()
function_names = []
registers, functions, uniques, extracts = {}, {}, {}, {}
internal_functions = {}
memory = {}
loaded = {}
flags = ["ZF", "CF", "OF", "SF"]
pointers = ["RSP", "RIP", "RBP", "EBP", "ESP"]

obj_dir = "./tests/obj/"
xml_dir = "./tests/xml/"
llvm_dir = "./tests/llvm_dir/"
xml_script = "GhidraToXML.java"

#The following variables need to be changed to your local directories
prj_dir = "/home/tej/GhidraProjects/"
prj_name = "testing.gpr"
ghidra_headless_loc = "/home/tej/buildsGhidra/ghidra_9.1.1_PUBLIC/support/analyzeHeadless"


def main():
    os.system("cd tests && make clean && make all && cd ..")
    print("\n***** Tests compiled, converting to XML *****\n")

    #cleanup XML folder
    for filename in os.listdir(xml_dir):
        os.remove(xml_dir + filename)

    for filename in os.listdir(obj_dir):
        os.system(ghidra_headless_loc + " " + prj_dir + " " + prj_name + " -import " + obj_dir + filename + " -postScript " + xml_script)
        convert()
        os.system("mv /tmp/output.xml ./tests/xml/" + filename)


def convert():
    root = et.parse('/tmp/output.xml').getroot()
    module = ir.Module(name="lifted")

    for register in root.find('globals').findall('register'):
        if register.get('name') in flags:
            var = ir.GlobalVariable(module, ir.IntType(1), register.get('name'))
            var.initializer = ir.Constant(ir.IntType(1), None)
            var.linkage = 'internal'
            registers[register.get('name')] = var
        elif register.get('name') in pointers:
            var = ir.GlobalVariable(module, ir.PointerType(ir.IntType(8)), register.get('name'))
            var.initializer = ir.Constant(ir.PointerType(ir.IntType(8)), None)
            var.linkage = 'internal'
            registers[register.get('name')] = var
        else:
            var = ir.GlobalVariable(module, ir.IntType(8 * int(register.get('size'))), register.get('name'))
            var.initializer = ir.Constant(ir.IntType(8 * int(register.get('size'))), None)
            var.linkage = 'internal'
            registers[register.get('name')] = var

    for memory_location in root.find('memory').findall('memory'):
        var = ir.GlobalVariable(module, ir.IntType(8 * int(memory_location.get('size'))), memory_location.get('name'))
        var.initializer = ir.Constant(ir.IntType(8 * int(memory_location.get('size'))), None)
        var.linkage = 'internal'
        memory[memory_location.get('name')] = var

    func_return = ir.VoidType()
    fnty = ir.FunctionType(func_return, [])
    ir_func = ir.Function(module, fnty, "intra_function_branch")
    internal_functions["intra_function_branch"] = ir_func

    func_return = ir.VoidType()
    fnty = ir.FunctionType(func_return, [])
    ir_func = ir.Function(module, fnty, "call_indirect")
    internal_functions["call_indirect"] = ir_func

    func_return = ir.VoidType()
    fnty = ir.FunctionType(func_return, [])
    ir_func = ir.Function(module, fnty, "special_subpiece")
    internal_functions["special_subpiece"] = ir_func

    for function in root.findall('function'):
        name = function.get('name')
        x = 0
        while name in function_names:
            x += 1
        if x != 0:
            name = name + "_" + str(x)
        function_names.append(name)
        address = function.get('address')
        functions[address] = [build_function(name, module), function]

    for address in functions:
        ir_func, function = functions[address]
        populate_func(ir_func, function)

    print(module)
    return 0


def populate_func(ir_func, function):
    builders, blocks = build_cfg(function, ir_func)
    if blocks == {}:
        return
    populate_cfg(function, builders, blocks)


def build_function(name, module):
    func_return = ir.VoidType()
    fnty = ir.FunctionType(func_return, [])
    ir_func = ir.Function(module, fnty, name)
    return ir_func


def build_cfg(function, ir_func):
    builders, blocks = {}, {}
    instructions = function.find("instructions")
    if instructions:
        block = ir_func.append_basic_block("entry")
        blocks["entry"] = block
        builders["entry"] = ir.IRBuilder(block)
        for instruction in instructions:
            address = instruction.find("address").text
            block = ir_func.append_basic_block(address)
            blocks[address] = block
            builders[address] = ir.IRBuilder(block)
    return builders, blocks


# noinspection DuplicatedCode
def populate_cfg(function, builders, blocks):
    builder = builders["entry"]
    stack_size = 10 * 1024 * 1024
    stack = builder.alloca(ir.IntType(8), stack_size, name="stack")
    stack_top = builder.gep(stack, [ir.Constant(int64, stack_size - 8)], name="stack_top")
    builder.store(stack_top, registers["RSP"])
    builder.branch(list(blocks.values())[1])
    block_iterator = 1
    instr = 0
    quiter = False
    for instruction in function.find("instructions"):
        if quiter:
            break
        address = instruction.find("address").text
        if address in builders:
            builder = builders[address]
        pcodes = instruction.find("pcodes")
        pc = 0
        no_branch = True
        for pcode in pcodes:
            pc += 1
            mnemonic = pcode.find("name")
            if mnemonic.text == "COPY":
                output = pcode.find("output")
                if output.text in flags and pcode.find("input_0").get("storage") == "constant":
                    source = ir.Constant(ir.IntType(1), int(pcode.find("input_0").text, 0))
                else:
                    source = fetch_input_varnode(builder, pcode.find("input_0"))
                update_output(builder, pcode.find("output"), source)
            elif mnemonic.text == "LOAD":
                input_1 = pcode.find("input_1")
                output = pcode.find("output")
                rhs = fetch_input_varnode(builder, input_1)
                if input_1.get("storage") == "unique" and output.get("storage") == "unique":
                    # This is incorrect. This is treating it as a copy, should load the memory address in the input 1
                    update_output(builder, output, rhs)
                else:
                    if input_1.text in loaded:
                        update_output(builder, output, loaded[input_1.text])
                    else:
                        if input_1.text in pointers:
                            rhs = builder.gep(rhs, [ir.Constant(int64, 0)])
                        result = builder.load(rhs)
                        update_output(builder, output, result)
            elif mnemonic.text == "STORE":
                input_1 = pcode.find("input_1")  # target
                input_2 = pcode.find("input_2")  # source
                rhs = fetch_input_varnode(builder, input_2)
                lhs = fetch_output_varnode(input_1)
                if not lhs.type.is_pointer:
                    lhs = builder.inttoptr(lhs, lhs.type.as_pointer())
                lhs2 = builder.gep(lhs, [ir.Constant(int64, 0)])
                if lhs2.type != rhs.type.as_pointer():
                    lhs2 = builder.bitcast(lhs2, rhs.type.as_pointer())
                builder.store(rhs, lhs2)
            elif mnemonic.text == "BRANCH":
                no_branch = False
                value = pcode.find("input_0").text[2:-2]
                if value in functions:
                    target = functions[value][0]
                    builder.call(target, [])
                elif value in blocks:
                    target = blocks[value]
                    builder.branch(target)
                else:
                    # weird jump into some label in another function
                    # might be solved with callbr instruction?
                    builder.call(internal_functions["intra_function_branch"], [])
            elif mnemonic.text == "CBRANCH":
                true_target = blocks[pcode.find("input_0").text[2:-2]]
                false_target = list(blocks.values())[block_iterator + 1]
                condition = fetch_input_varnode(builder, pcode.find("input_1"))
                no_branch = False
                builder.cbranch(condition, true_target, false_target)
            elif mnemonic.text == "BRANCHIND":
                no_branch = False
                target = fetch_input_varnode(builder, pcode.find("input_0"))
                builder.branch_indirect(target)
            elif mnemonic.text == "CALL":
                target = functions[pcode.find("input_0").text[2:-2]][0]
                builder.call(target, [])
            elif mnemonic.text == "CALLIND":
                # target = pcode.find("input_0").text[2:-2]
                builder.call(internal_functions["call_indirect"], [])
            elif mnemonic.text == "USERDEFINED":
                raise Exception("Not implemented")
            elif mnemonic.text == "RETURN":
                input_1 = pcode.find("input_1")
                no_branch = False
                if input_1 is None:
                    builder.ret_void()
                else:
                    raise Exception("Return value being passed")
            elif mnemonic.text == "PIECE":
                raise Exception("PIECE operation needs to be tested")
            elif mnemonic.text == "SUBPIECE":
                output = pcode.find("output")
                input_0 = pcode.find("input_0")
                input_1 = pcode.find("input_1")
                if input_1.text == "0x0":
                    val = fetch_input_varnode(builder, input_0)
                    result = builder.trunc(val, ir.IntType(int(output.get("size")) * 8))
                    update_output(builder, output, result)
                else:
                    builder.call(internal_functions["special_subpiece"], [])
            elif mnemonic.text == "INT_EQUAL":
                lhs = fetch_input_varnode(builder, pcode.find("input_0"))
                rhs = fetch_input_varnode(builder, pcode.find("input_1"))
                lhs, rhs = int_comparison_check_inputs(builder, lhs, rhs)
                result = builder.icmp_unsigned('==', lhs, rhs)
                update_output(builder, pcode.find("output"), result)
            elif mnemonic.text == "INT_NOTEQUAL":
                lhs = fetch_input_varnode(builder, pcode.find("input_0"))
                rhs = fetch_input_varnode(builder, pcode.find("input_1"))
                lhs, rhs = int_comparison_check_inputs(builder, lhs, rhs)
                result = builder.icmp_unsigned('!=', lhs, rhs)
                update_output(builder, pcode.find("output"), result)
            elif mnemonic.text == "INT_LESS":
                lhs = fetch_input_varnode(builder, pcode.find("input_0"))
                rhs = fetch_input_varnode(builder, pcode.find("input_1"))
                lhs, rhs = int_comparison_check_inputs(builder, lhs, rhs)
                result = builder.icmp_unsigned('<', lhs, rhs)
                update_output(builder, pcode.find("output"), result)
            elif mnemonic.text == "INT_SLESS":
                lhs = fetch_input_varnode(builder, pcode.find("input_0"))
                rhs = fetch_input_varnode(builder, pcode.find("input_1"))
                lhs, rhs = int_comparison_check_inputs(builder, lhs, rhs)
                result = builder.icmp_signed('<', lhs, rhs)
                update_output(builder, pcode.find("output"), result)
            elif mnemonic.text == "INT_LESSEQUAL":
                lhs = fetch_input_varnode(builder, pcode.find("input_0"))
                rhs = fetch_input_varnode(builder, pcode.find("input_1"))
                lhs, rhs = int_comparison_check_inputs(builder, lhs, rhs)
                result = builder.icmp_unsigned('<=', lhs, rhs)
                update_output(builder, pcode.find("output"), result)
            elif mnemonic.text == "INT_SLESS_EQUAL":
                lhs = fetch_input_varnode(builder, pcode.find("input_0"))
                rhs = fetch_input_varnode(builder, pcode.find("input_1"))
                lhs, rhs = int_comparison_check_inputs(builder, lhs, rhs)
                result = builder.icmp_signed('<=', lhs, rhs)
                update_output(builder, pcode.find("output"), result)
            elif mnemonic.text == "INT_ZEXT":
                rhs = fetch_input_varnode(builder, pcode.find("input_0"))
                output = builder.zext(rhs, ir.IntType(int(pcode.find("output").get("size")) * 8))
                update_output(builder, pcode.find("output"), output)
            elif mnemonic.text == "INT_SEXT":
                rhs = fetch_input_varnode(builder, pcode.find("input_0"))
                output = builder.sext(rhs, ir.IntType(int(pcode.find("output").get("size")) * 8))
                update_output(builder, pcode.find("output"), output)
            elif mnemonic.text == "INT_ADD":
                input_0 = pcode.find("input_0")
                input_1 = pcode.find("input_1")
                lhs = fetch_input_varnode(builder, input_0)
                rhs = fetch_input_varnode(builder, input_1)
                target = fetch_output_varnode(pcode.find("output"))
                if input_0.text in pointers and input_1.get("storage") == "constant":
                    result = builder.gep(lhs, [ir.Constant(int64, int(input_1.text, 16))])
                else:
                    lhs, rhs = int_check_inputs(builder, lhs, rhs, target)
                    result = builder.add(lhs, rhs)
                update_output(builder, pcode.find("output"), result)
            elif mnemonic.text == "INT_SUB":
                input_0 = pcode.find("input_0")
                input_1 = pcode.find("input_1")
                lhs = fetch_input_varnode(builder, input_0)
                rhs = fetch_input_varnode(builder, input_1)
                target = fetch_output_varnode(pcode.find("output"))
                if input_0.text in pointers and input_1.get("storage") == "constant":
                    result = builder.gep(lhs, [ir.Constant(int64, -int(input_1.text, 16))])
                else:
                    lhs, rhs = int_check_inputs(builder, lhs, rhs, target)
                    result = builder.sub(lhs, rhs)
                update_output(builder, pcode.find("output"), result)
            elif mnemonic.text == "INT_CARRY":
                lhs = fetch_input_varnode(builder, pcode.find("input_0"))
                rhs = fetch_input_varnode(builder, pcode.find("input_1"))
                lhs, rhs = int_comparison_check_inputs(builder, lhs, rhs)
                result = builder.uadd_with_overflow(lhs, rhs)
                result = builder.extract_value(result, 1)
                update_output(builder, pcode.find("output"), result)
            elif mnemonic.text == "INT_SCARRY":
                lhs = fetch_input_varnode(builder, pcode.find("input_0"))
                rhs = fetch_input_varnode(builder, pcode.find("input_1"))
                lhs, rhs = int_comparison_check_inputs(builder, lhs, rhs)
                result = builder.sadd_with_overflow(lhs, rhs)
                result = builder.extract_value(result, 1)
                update_output(builder, pcode.find("output"), result)
            elif mnemonic.text == "INT_SBORROW":
                lhs = fetch_input_varnode(builder, pcode.find("input_0"))
                rhs = fetch_input_varnode(builder, pcode.find("input_1"))
                lhs, rhs = int_comparison_check_inputs(builder, lhs, rhs)
                result = builder.ssub_with_overflow(lhs, rhs)
                result = builder.extract_value(result, 1)
                update_output(builder, pcode.find("output"), result)
            elif mnemonic.text == "INT_2COMP":
                val = fetch_input_varnode(builder, pcode.find("input_0"))
                result = builder.not_(val)
                update_output(builder, pcode.find("output"), result)
            elif mnemonic.text == "INT_NEGATE":
                val = fetch_input_varnode(builder, pcode.find("input_0"))
                result = builder.neg(val)
                update_output(builder, pcode.find("output"), result)
            elif mnemonic.text == "INT_XOR":
                lhs = fetch_input_varnode(builder, pcode.find("input_0"))
                rhs = fetch_input_varnode(builder, pcode.find("input_1"))
                target = fetch_output_varnode(pcode.find("output"))
                lhs, rhs = int_check_inputs(builder, lhs, rhs, target)
                output = builder.xor(lhs, rhs)
                update_output(builder, pcode.find("output"), output)
            elif mnemonic.text == "INT_AND":
                lhs = fetch_input_varnode(builder, pcode.find("input_0"))
                rhs = fetch_input_varnode(builder, pcode.find("input_1"))
                target = fetch_output_varnode(pcode.find("output"))
                lhs, rhs = int_check_inputs(builder, lhs, rhs, target)
                output = builder.and_(lhs, rhs)
                update_output(builder, pcode.find("output"), output)
            elif mnemonic.text == "INT_OR":
                lhs = fetch_input_varnode(builder, pcode.find("input_0"))
                rhs = fetch_input_varnode(builder, pcode.find("input_1"))
                target = fetch_output_varnode(pcode.find("output"))
                lhs, rhs = int_check_inputs(builder, lhs, rhs, target)
                output = builder.or_(lhs, rhs)
                update_output(builder, pcode.find("output"), output)
            elif mnemonic.text == "INT_LEFT":
                lhs = fetch_input_varnode(builder, pcode.find("input_0"))
                rhs = fetch_input_varnode(builder, pcode.find("input_1"))
                lhs, rhs = check_shift_inputs(builder, lhs, rhs)
                output = builder.shl(lhs, rhs)
                update_output(builder, pcode.find("output"), output)
            elif mnemonic.text == "INT_RIGHT":
                lhs = fetch_input_varnode(builder, pcode.find("input_0"))
                rhs = fetch_input_varnode(builder, pcode.find("input_1"))
                lhs, rhs = check_shift_inputs(builder, lhs, rhs)
                output = builder.lshr(lhs, rhs)
                update_output(builder, pcode.find("output"), output)
            elif mnemonic.text == "INT_SRIGHT":
                lhs = fetch_input_varnode(builder, pcode.find("input_0"))
                rhs = fetch_input_varnode(builder, pcode.find("input_1"))
                lhs, rhs = check_shift_inputs(builder, lhs, rhs)
                output = builder.ashr(lhs, rhs)
                update_output(builder, pcode.find("output"), output)
            elif mnemonic.text == "INT_MULT":
                lhs = fetch_input_varnode(builder, pcode.find("input_0"))
                rhs = fetch_input_varnode(builder, pcode.find("input_1"))
                target = fetch_output_varnode(pcode.find("output"))
                lhs, rhs = int_check_inputs(builder, lhs, rhs, target)
                output = builder.mul(lhs, rhs)
                update_output(builder, pcode.find("output"), output)
            elif mnemonic.text == "INT_DIV":
                lhs = fetch_input_varnode(builder, pcode.find("input_0"))
                rhs = fetch_input_varnode(builder, pcode.find("input_1"))
                target = fetch_output_varnode(pcode.find("output"))
                lhs, rhs = int_check_inputs(builder, lhs, rhs, target)
                output = builder.div(lhs, rhs)
                update_output(builder, pcode.find("output"), output)
            elif mnemonic.text == "INT_REM":
                lhs = fetch_input_varnode(builder, pcode.find("input_0"))
                rhs = fetch_input_varnode(builder, pcode.find("input_1"))
                target = fetch_output_varnode(pcode.find("output"))
                lhs, rhs = int_check_inputs(builder, lhs, rhs, target)
                output = builder.urem(lhs, rhs)
                update_output(builder, pcode.find("output"), output)
            elif mnemonic.text == "INT_SDIV":
                lhs = fetch_input_varnode(builder, pcode.find("input_0"))
                rhs = fetch_input_varnode(builder, pcode.find("input_1"))
                target = fetch_output_varnode(pcode.find("output"))
                lhs, rhs = int_check_inputs(builder, lhs, rhs, target)
                output = builder.sdiv(lhs, rhs)
                update_output(builder, pcode.find("output"), output)
            elif mnemonic.text == "INT_SREM":
                lhs = fetch_input_varnode(builder, pcode.find("input_0"))
                rhs = fetch_input_varnode(builder, pcode.find("input_1"))
                target = fetch_output_varnode(pcode.find("output"))
                lhs, rhs = int_check_inputs(builder, lhs, rhs, target)
                output = builder.srem(lhs, rhs)
                update_output(builder, pcode.find("output"), output)
            elif mnemonic.text == "BOOL_NEGATE":
                lhs = fetch_input_varnode(builder, pcode.find("input_0"))
                result = builder.neg(lhs)
                update_output(builder, pcode.find("output"), result)
            elif mnemonic.text == "BOOL_XOR":
                lhs = fetch_input_varnode(builder, pcode.find("input_0"))
                rhs = fetch_input_varnode(builder, pcode.find("input_1"))
                result = builder.xor(lhs, rhs)
                update_output(builder, pcode.find("output"), result)
            elif mnemonic.text == "BOOL_AND":
                lhs = fetch_input_varnode(builder, pcode.find("input_0"))
                rhs = fetch_input_varnode(builder, pcode.find("input_1"))
                result = builder.and_(lhs, rhs)
                update_output(builder, pcode.find("output"), result)
            elif mnemonic.text == "BOOL_OR":
                lhs = fetch_input_varnode(builder, pcode.find("input_0"))
                rhs = fetch_input_varnode(builder, pcode.find("input_1"))
                result = builder.or_(lhs, rhs)
                update_output(builder, pcode.find("output"), result)
            elif mnemonic.text == "FLOAT_EQUAL":
                raise Exception("Not implemented")
            elif mnemonic.text == "FLOAT_NOTEQUAL":
                raise Exception("Not implemented")
            elif mnemonic.text == "FLOAT_LESS":
                raise Exception("Not implemented")
            elif mnemonic.text == "FLOAT_LESSEQUAL":
                raise Exception("Not implemented")
            elif mnemonic.text == "FLOAT_ADD":
                raise Exception("Not implemented")
            elif mnemonic.text == "FLOAT_SUB":
                raise Exception("Not implemented")
            elif mnemonic.text == "FLOAT_MULT":
                raise Exception("Not implemented")
            elif mnemonic.text == "FLOAT_DIV":
                raise Exception("Not implemented")
            elif mnemonic.text == "FLOAT_NEG":
                raise Exception("Not implemented")
            elif mnemonic.text == "FLOAT_ABS":
                raise Exception("Not implemented")
            elif mnemonic.text == "FLOAT_SQRT":
                raise Exception("Not implemented")
            elif mnemonic.text == "FLOAT_CEIL":
                raise Exception("Not implemented")
            elif mnemonic.text == "FLOAT_FLOOR":
                raise Exception("Not implemented")
            elif mnemonic.text == "FLOAT_ROUND":
                raise Exception("Not implemented")
            elif mnemonic.text == "FLOAT_NAN":
                raise Exception("Not implemented")
            elif mnemonic.text == "INT2FLOAT":
                raise Exception("Not implemented")
            elif mnemonic.text == "FLOAT2FLOAT":
                raise Exception("Not implemented")
            elif mnemonic.text == "TRUNC":
                raise Exception("Not implemented")
            elif mnemonic.text == "CPOOLREF":
                raise Exception("Not implemented")
            elif mnemonic.text == "NEW":
                raise Exception("Not implemented")
            elif mnemonic.text == "MULTIEQUAL":
                raise Exception("Not implemented")
            elif mnemonic.text == "INDIRECT":
                raise Exception("Not implemented")
            elif mnemonic.text == "PTRADD":
                raise Exception("Not implemented")
            elif mnemonic.text == "PTRSUB":
                raise Exception("Not implemented")
            elif mnemonic.text == "CAST":
                raise Exception("Not implemented")
            else:
                raise Exception("Not a standard pcode instruction")
        block_iterator += 1
        instr += 1
        if block_iterator < len(blocks) and no_branch:
            builder.branch(list(blocks.values())[block_iterator])


def fetch_input_varnode(builder, name):
    var_type = name.get("storage")
    var_size = int(name.get("size")) * 8
    if var_type == "register":
        if name.text not in list(loaded.keys()):
            loaded[name.text] = builder.load(registers[name.text])
        return loaded[name.text]
    elif var_type == "unique":
        if name.text not in list(uniques.keys()):
            raise Exception("Temporary variable referenced before defined")
        return uniques[name.text]
    elif var_type == "constant":
        var = ir.Constant(ir.IntType(var_size), int(name.text, 0))
        return var
    elif var_type == "memory":
        if name.text not in list(loaded.keys()):
            loaded[name.text] = memory[name.text]
        return loaded[name.text]


def update_output(builder, name, output):
    var_type = name.get("storage")
    if var_type == "register":
        reg = registers[name.text]
        if reg.type != output.type.as_pointer():
            reg = builder.bitcast(reg, output.type.as_pointer())
        builder.store(output, reg)
    elif var_type == "unique":
        uniques[name.text] = output


def fetch_output_varnode(name):
    var_type = name.get("storage")
    if var_type == "register":
        return registers[name.text]
    elif var_type == "unique":
        if name.text not in uniques:
            uniques[name.text] = None
        return uniques[name.text]


def int_check_inputs(builder, lhs, rhs, target):
    if lhs.type == rhs.type:
        return lhs, rhs
    else:
        lhs = builder.ptrtoint(lhs, rhs.type)
        return lhs, rhs


def check_shift_inputs(builder, lhs, rhs):
    if lhs.type != rhs.type:
        rhs = builder.zext(rhs, lhs.type)
    return lhs, rhs


def int_comparison_check_inputs(builder, lhs, rhs):
    # For integer comparison operations. We assume rhs is the correct type.
    if lhs.type.is_pointer:
        lhs = builder.ptrtoint(lhs, rhs.type)
    elif rhs.type.is_pointer:
        rhs = builder.ptrtoint(rhs, lhs.type)
    return lhs, rhs


if __name__ == "__main__":
    main()
