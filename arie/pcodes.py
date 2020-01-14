from llvmlite import ir
import xml.etree.ElementTree as ET

int32 = ir.IntType(32)
int64 = ir.IntType(64)
int1 = ir.IntType(1)
void_type = ir.VoidType()
registers, functions, uniques, extracts = {}, {}, {}, {}
memory = {}
loaded = {}
flags = ["ZF", "CF", "OF", "SF"]
pointers = ["RSP", "RIP", "RBP", "EBP"]


def main():
    root = ET.parse('/tmp/output.xml').getroot()
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

    for function in root.findall('function'):
        name = function.get('name')
        if name in ["main"]:
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
        instr += 1
        address = instruction.find("address").text
        if address in builders:
            builder = builders[address]
        pcodes = instruction.find("pcodes")
        pc = 0
        no_branch = True
        for pcode in pcodes:
            # if instr == 9 and pc == 0:
            #     quiter = True
            #     break
            pc += 1
            mnemonic = pcode.find("name")
            if mnemonic.text == "COPY":
                output = pcode.find("output")
                input_0 = pcode.find("input_0")
                source = fetch_input_varnode(builder, input_0)
                if output.get("storage") == "unique":
                    uniques[output.text] = source
                else:
                    target = fetch_output_varnode(builder, output)
                    result = builder.bitcast(source, target.type)
                    update_output(builder, output, result)
            elif mnemonic.text == "LOAD":
                # input_1 = pcode.find("input_0")  # memory chunk
                input_1 = pcode.find("input_1")
                output = pcode.find("output")
                rhs = fetch_input_varnode(builder, input_1)
                if input_1.text in pointers:
                    rhs = builder.gep(rhs, [ir.Constant(int64, 0)])
                result = builder.load(rhs)
                update_output(builder, output, result)
            elif mnemonic.text == "STORE":
                # input_0 = pcode.find("input_0")  # memory chunk
                input_1 = pcode.find("input_1")
                input_2 = pcode.find("input_2")
                rhs = fetch_input_varnode(builder, input_2)
                lhs = fetch_output_varnode(builder, input_1)
                lhs2 = builder.gep(lhs, [ir.Constant(int64, 0)])
                if lhs2.type != rhs.type.as_pointer():
                    lhs2 = builder.bitcast(lhs2, rhs.type.as_pointer())
                builder.store(rhs, lhs2)
            elif mnemonic.text == "BRANCH":
                no_branch = False
                target = blocks[pcode.find("input_0").text[2:-2]]
                builder.branch(target)
            elif mnemonic.text == "CBRANCH":
                true_target = blocks[pcode.find("input_0").text[2:-2]]
                false_target = list(blocks.values())[block_iterator+1]
                condition = fetch_input_varnode(builder, pcode.find("input_1"))
                no_branch = False
                builder.cbranch(condition, true_target, false_target)
            elif mnemonic.text == "BRANCHIND":
                no_branch = False
                target = fetch_input_varnode(builder, pcode.find("input_0"))
                builder.branch_indirect(target)
            elif mnemonic.text == "CALL":
                pass
            elif mnemonic.text == "CALLIND":
                pass
            elif mnemonic.text == "USERDEFINED":
                pass
            elif mnemonic.text == "RETURN":
                input_1 = pcode.find("input_1")
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
                    raise Exception("Need special function to model this bit extraction")
            elif mnemonic.text == "INT_EQUAL":
                lhs = fetch_input_varnode(builder, pcode.find("input_0"))
                rhs = fetch_input_varnode(builder, pcode.find("input_1"))
                if lhs.type == rhs.type.as_pointer():
                    lhs = builder.ptrtoint(lhs, rhs.type)
                elif pcode.find("input_0").text in pointers:
                    lhs = builder.bitcast(lhs, rhs.type)
                output = builder.icmp_unsigned('==', lhs, rhs)
                update_output(builder, pcode.find("output"), output)
            elif mnemonic.text == "INT_NOTEQUAL":
                lhs = fetch_input_varnode(builder, pcode.find("input_0"))
                rhs = fetch_input_varnode(builder, pcode.find("input_1"))
                if lhs.type == rhs.type.as_pointer():
                    lhs = builder.ptrtoint(lhs, rhs.type)
                elif pcode.find("input_0").text in pointers:
                    lhs = builder.bitcast(lhs, rhs.type)
                output = builder.icmp_unsigned('!=', lhs, rhs)
                update_output(builder, pcode.find("output"), output)
            elif mnemonic.text == "INT_LESS":
                lhs = fetch_input_varnode(builder, pcode.find("input_0"))
                rhs = fetch_input_varnode(builder, pcode.find("input_1"))
                if lhs.type == rhs.type.as_pointer():
                    lhs = builder.ptrtoint(lhs, rhs.type)
                elif pcode.find("input_0").text in pointers:
                    lhs = builder.bitcast(lhs, rhs.type)
                output = builder.icmp_unsigned('<', lhs, rhs)
                update_output(builder, pcode.find("output"), output)
            elif mnemonic.text == "INT_SLESS":
                lhs = fetch_input_varnode(builder, pcode.find("input_0"))
                rhs = fetch_input_varnode(builder, pcode.find("input_1"))
                if lhs.type == rhs.type.as_pointer():
                    lhs = builder.ptrtoint(lhs, rhs.type)
                elif pcode.find("input_0").text in pointers:
                    lhs = builder.bitcast(lhs, rhs.type)
                output = builder.icmp_signed('<', lhs, rhs)
                update_output(builder, pcode.find("output"), output)
            elif mnemonic.text == "INT_LESSEQUAL":
                lhs = fetch_input_varnode(builder, pcode.find("input_0"))
                rhs = fetch_input_varnode(builder, pcode.find("input_1"))
                if lhs.type == rhs.type.as_pointer():
                    lhs = builder.ptrtoint(lhs, rhs.type)
                elif pcode.find("input_0").text in pointers:
                    lhs = builder.bitcast(lhs, rhs.type)
                output = builder.icmp_unsigned('<=', lhs, rhs)
                update_output(builder, pcode.find("output"), output)
            elif mnemonic.text == "INT_SLESS":
                lhs = fetch_input_varnode(builder, pcode.find("input_0"))
                rhs = fetch_input_varnode(builder, pcode.find("input_1"))
                if lhs.type == rhs.type.as_pointer():
                    lhs = builder.ptrtoint(lhs, rhs.type)
                elif pcode.find("input_0").text in pointers:
                    lhs = builder.bitcast(lhs, rhs.type)
                output = builder.icmp_signed('<=', lhs, rhs)
                update_output(builder, pcode.find("output"), output)
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
                if input_0.text in pointers and input_1.get("storage") == "constant":
                    result = builder.gep(lhs, [ir.Constant(int64, int(input_1.text, 16))])
                    update_output(builder, pcode.find("output"), result)
                elif lhs.type == rhs.type.as_pointer():
                    lhs = builder.ptrtoint(lhs, rhs.type)
                    output = builder.add(lhs, rhs)
                    update_output(builder, pcode.find("output"), output)
                else:
                    output = builder.add(lhs, rhs)
                    update_output(builder, pcode.find("output"), output)
            elif mnemonic.text == "INT_SUB":
                input_0 = pcode.find("input_0")
                input_1 = pcode.find("input_1")
                lhs = fetch_input_varnode(builder, input_0)
                rhs = fetch_input_varnode(builder, input_1)
                if input_0.text in pointers and input_1.get("storage") == "constant":
                    result = builder.gep(lhs, [ir.Constant(int64, -int(input_1.text, 16))])
                    update_output(builder, pcode.find("output"), result)
                elif lhs.type == rhs.type.as_pointer():
                    lhs = builder.ptrtoint(lhs, rhs.type)
                    output = builder.sub(lhs, rhs)
                    update_output(builder, pcode.find("output"), output)
                else:
                    output = builder.sub(lhs, rhs)
                    update_output(builder, pcode.find("output"), output)
            elif mnemonic.text == "INT_CARRY":
                lhs = fetch_input_varnode(builder, pcode.find("input_0"))
                rhs = fetch_input_varnode(builder, pcode.find("input_1"))
                if lhs.type == rhs.type.as_pointer():
                    lhs = builder.ptrtoint(lhs, rhs.type)
                elif pcode.find("input_0").text in pointers:
                    lhs = builder.bitcast(lhs, rhs.type)
                output = builder.uadd_with_overflow(lhs, rhs)
                output = builder.extract_value(output, 1)
                update_output(builder, pcode.find("output"), output)
            elif mnemonic.text == "INT_SCARRY":
                lhs = fetch_input_varnode(builder, pcode.find("input_0"))
                rhs = fetch_input_varnode(builder, pcode.find("input_1"))
                if lhs.type == rhs.type.as_pointer():
                    lhs = builder.ptrtoint(lhs, rhs.type)
                elif pcode.find("input_0").text in pointers:
                    lhs = builder.bitcast(lhs, rhs.type)
                output = builder.sadd_with_overflow(lhs, rhs)
                output = builder.extract_value(output, 1)
                update_output(builder, pcode.find("output"), output)
            elif mnemonic.text == "INT_SBORROW":
                lhs = fetch_input_varnode(builder, pcode.find("input_0"))
                rhs = fetch_input_varnode(builder, pcode.find("input_1"))
                if lhs.type == rhs.type.as_pointer():
                    lhs = builder.ptrtoint(lhs, rhs.type)
                elif pcode.find("input_0").text in pointers:
                    lhs = builder.bitcast(lhs, rhs.type)
                output = builder.sadd_with_overflow(lhs, rhs)
                output = builder.extract_value(output, 1)
                update_output(builder, pcode.find("output"), output)
            elif mnemonic.text == "INT_2COMP":
                lhs = fetch_input_varnode(builder, pcode.find("input_0"))
                rhs = fetch_input_varnode(builder, pcode.find("input_1"))
                if lhs.type == rhs.type.as_pointer():
                    lhs = builder.ptrtoint(lhs, rhs.type)
                elif pcode.find("input_0").text in pointers:
                    lhs = builder.bitcast(lhs, rhs.type)
                output = builder.not_(lhs, rhs)
                update_output(builder, pcode.find("output"), output)
            elif mnemonic.text == "INT_NEGATE":
                lhs = fetch_input_varnode(builder, pcode.find("input_0"))
                rhs = fetch_input_varnode(builder, pcode.find("input_1"))
                if lhs.type == rhs.type.as_pointer():
                    lhs = builder.ptrtoint(lhs, rhs.type)
                elif pcode.find("input_0").text in pointers:
                    lhs = builder.bitcast(lhs, rhs.type)
                output = builder.neg(lhs, rhs)
                update_output(builder, pcode.find("output"), output)
            elif mnemonic.text == "INT_XOR":
                lhs = fetch_input_varnode(builder, pcode.find("input_0"))
                rhs = fetch_input_varnode(builder, pcode.find("input_1"))
                if lhs.type == rhs.type.as_pointer():
                    lhs = builder.ptrtoint(lhs, rhs.type)
                elif pcode.find("input_0").text in pointers:
                    lhs = builder.bitcast(lhs, rhs.type)
                output = builder.xor(lhs, rhs)
                update_output(builder, pcode.find("output"), output)
            elif mnemonic.text == "INT_AND":
                lhs = fetch_input_varnode(builder, pcode.find("input_0"))
                rhs = fetch_input_varnode(builder, pcode.find("input_1"))
                if lhs.type == rhs.type.as_pointer():
                    lhs = builder.ptrtoint(lhs, rhs.type)
                elif pcode.find("input_0").text in pointers:
                    lhs = builder.bitcast(lhs, rhs.type)
                output = builder.and_(lhs, rhs)
                update_output(builder, pcode.find("output"), output)
            elif mnemonic.text == "INT_OR":
                lhs = fetch_input_varnode(builder, pcode.find("input_0"))
                rhs = fetch_input_varnode(builder, pcode.find("input_1"))
                if lhs.type == rhs.type.as_pointer():
                    lhs = builder.ptrtoint(lhs, rhs.type)
                elif pcode.find("input_0").text in pointers:
                    lhs = builder.bitcast(lhs, rhs.type)
                output = builder.or_(lhs, rhs)
                update_output(builder, pcode.find("output"), output)
            elif mnemonic.text == "INT_LEFT":
                lhs = fetch_input_varnode(builder, pcode.find("input_0"))
                rhs = fetch_input_varnode(builder, pcode.find("input_1"))
                if lhs.type == rhs.type.as_pointer():
                    lhs = builder.ptrtoint(lhs, rhs.type)
                elif pcode.find("input_0").text in pointers:
                    lhs = builder.bitcast(lhs, rhs.type)
                else:
                    lhs = builder.bitcast(lhs, ir.IntType(int(pcode.find("output").get("size")) * 8))
                    rhs = builder.bitcast(lhs, ir.IntType(int(pcode.find("output").get("size")) * 8))
                output = builder.shl(lhs, rhs)
                update_output(builder, pcode.find("output"), output)
            elif mnemonic.text == "INT_RIGHT":
                lhs = fetch_input_varnode(builder, pcode.find("input_0"))
                rhs = fetch_input_varnode(builder, pcode.find("input_1"))
                if lhs.type == rhs.type.as_pointer():
                    lhs = builder.ptrtoint(lhs, rhs.type)
                elif pcode.find("input_0").text in pointers:
                    lhs = builder.bitcast(lhs, rhs.type)
                else:
                    lhs = builder.bitcast(lhs, ir.IntType(int(pcode.find("output").get("size"))*8))
                    rhs = builder.bitcast(lhs, ir.IntType(int(pcode.find("output").get("size")) * 8))
                output = builder.lshr(lhs, rhs)
                update_output(builder, pcode.find("output"), output)
            elif mnemonic.text == "INT_SRIGHT":
                lhs = fetch_input_varnode(builder, pcode.find("input_0"))
                rhs = fetch_input_varnode(builder, pcode.find("input_1"))
                if lhs.type == rhs.type.as_pointer():
                    lhs = builder.ptrtoint(lhs, rhs.type)
                elif pcode.find("input_0").text in pointers:
                    lhs = builder.bitcast(lhs, rhs.type)
                else:
                    lhs = builder.bitcast(lhs, ir.IntType(int(pcode.find("output").get("size")) * 8))
                    rhs = builder.bitcast(lhs, ir.IntType(int(pcode.find("output").get("size")) * 8))
                output = builder.ashr(lhs, rhs)
                update_output(builder, pcode.find("output"), output)
            elif mnemonic.text == "INT_MULT":
                lhs = fetch_input_varnode(builder, pcode.find("input_0"))
                rhs = fetch_input_varnode(builder, pcode.find("input_1"))
                if lhs.type == rhs.type.as_pointer():
                    lhs = builder.ptrtoint(lhs, rhs.type)
                elif pcode.find("input_0").text in pointers:
                    lhs = builder.bitcast(lhs, rhs.type)
                output = builder.mul(lhs, rhs)
                update_output(builder, pcode.find("output"), output)
            elif mnemonic.text == "INT_DIV":
                lhs = fetch_input_varnode(builder, pcode.find("input_0"))
                rhs = fetch_input_varnode(builder, pcode.find("input_1"))
                if lhs.type == rhs.type.as_pointer():
                    lhs = builder.ptrtoint(lhs, rhs.type)
                elif pcode.find("input_0").text in pointers:
                    lhs = builder.bitcast(lhs, rhs.type)
                output = builder.div(lhs, rhs)
                update_output(builder, pcode.find("output"), output)
            elif mnemonic.text == "INT_REM":
                lhs = fetch_input_varnode(builder, pcode.find("input_0"))
                rhs = fetch_input_varnode(builder, pcode.find("input_1"))
                if lhs.type == rhs.type.as_pointer():
                    lhs = builder.ptrtoint(lhs, rhs.type)
                elif pcode.find("input_0").text in pointers:
                    lhs = builder.bitcast(lhs, rhs.type)
                output = builder.urem(lhs, rhs)
                update_output(builder, pcode.find("output"), output)
            elif mnemonic.text == "INT_SDIV":
                lhs = fetch_input_varnode(builder, pcode.find("input_0"))
                rhs = fetch_input_varnode(builder, pcode.find("input_1"))
                if lhs.type == rhs.type.as_pointer():
                    lhs = builder.ptrtoint(lhs, rhs.type)
                elif pcode.find("input_0").text in pointers:
                    lhs = builder.bitcast(lhs, rhs.type)
                output = builder.sdiv(lhs, rhs)
                update_output(builder, pcode.find("output"), output)
            elif mnemonic.text == "INT_SREM":
                lhs = fetch_input_varnode(builder, pcode.find("input_0"))
                rhs = fetch_input_varnode(builder, pcode.find("input_1"))
                if lhs.type == rhs.type.as_pointer():
                    lhs = builder.ptrtoint(lhs, rhs.type)
                elif pcode.find("input_0").text in pointers:
                    lhs = builder.bitcast(lhs, rhs.type)
                output = builder.srem(lhs, rhs)
                update_output(builder, pcode.find("output"), output)
            elif mnemonic.text == "BOOL_NEGATE":
                input = fetch_input_varnode(builder, pcode.find("input_0"))
                output = builder.neg(input)
                update_output(builder, pcode.find("output"), output)
            elif mnemonic.text == "BOOL_XOR":
                lhs = fetch_input_varnode(builder, pcode.find("input_0"))
                rhs = fetch_input_varnode(builder, pcode.find("input_1"))
                if lhs.type != rhs.type:
                    builder.bitcast(lhs, ir.IntType(1))
                    builder.bitcast(rhs, ir.IntType(1))
                output = builder.xor(lhs,rhs)
                update_output(builder, pcode.find("output"), output)
            elif mnemonic.text == "BOOL_AND":
                lhs = fetch_input_varnode(builder, pcode.find("input_0"))
                rhs = fetch_input_varnode(builder, pcode.find("input_1"))
                if lhs.type != rhs.type:
                    builder.bitcast(lhs, ir.IntType(1))
                    builder.bitcast(rhs, ir.IntType(1))
                output = builder.and_(lhs, rhs)
                update_output(builder, pcode.find("output"), output)
            elif mnemonic.text == "BOOL_OR":
                lhs = fetch_input_varnode(builder, pcode.find("input_0"))
                rhs = fetch_input_varnode(builder, pcode.find("input_1"))
                if lhs.type != rhs.type:
                    builder.bitcast(lhs, ir.IntType(1))
                    builder.bitcast(rhs, ir.IntType(1))
                output = builder.or_(lhs, rhs)
                update_output(builder, pcode.find("output"), output)
            elif mnemonic.text == "FLOAT_EQUAL":
                pass
            elif mnemonic.text == "FLOAT_NOTEQUAL":
                pass
            elif mnemonic.text == "FLOAT_LESS":
                pass
            elif mnemonic.text == "FLOAT_LESSEQUAL":
                pass
            elif mnemonic.text == "FLOAT_ADD":
                pass
            elif mnemonic.text == "FLOAT_SUB":
                pass
            elif mnemonic.text == "FLOAT_MULT":
                pass
            elif mnemonic.text == "FLOAT_DIV":
                pass
            elif mnemonic.text == "FLOAT_NEG":
                pass
            elif mnemonic.text == "FLOAT_ABS":
                pass
            elif mnemonic.text == "FLOAT_SQRT":
                pass
            elif mnemonic.text == "FLOAT_CEIL":
                pass
            elif mnemonic.text == "FLOAT_FLOOR":
                pass
            elif mnemonic.text == "FLOAT_ROUND":
                pass
            elif mnemonic.text == "FLOAT_NAN":
                pass
            elif mnemonic.text == "INT2FLOAT":
                pass
            elif mnemonic.text == "FLOAT2FLOAT":
                pass
            elif mnemonic.text == "TRUNC":
                pass
            elif mnemonic.text == "CPOOLREF":
                pass
            elif mnemonic.text == "NEW":
                pass
            elif mnemonic.text == "MULTIEQUAL":
                pass
            elif mnemonic.text == "INDIRECT":
                pass
            elif mnemonic.text == "PTRADD":
                pass
            elif mnemonic.text == "PTRSUB":
                pass
            elif mnemonic.text == "CAST":
                pass
            else:
                raise Exception("Not a standard pcode instruction")
        block_iterator += 1
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
    var_size = int(name.get("size")) * 8
    if var_type == "register":
        reg = registers[name.text]
        if reg.type != output.type.as_pointer():
            reg = builder.bitcast(reg, output.type.as_pointer())
        builder.store(output, reg)
    elif var_type == "unique":
        uniques[name.text] = output


def fetch_output_varnode(builder, name):
    var_type = name.get("storage")
    var_size = int(name.get("size")) * 8
    if var_type == "register":
        return registers[name.text]
    elif var_type == "unique":
        return uniques[name.text]


if __name__ == "__main__":
    main()
