from llvmlite import ir
import xml.etree.ElementTree as ET
import fileinput
import sys

int32 = ir.IntType(32)
int64 = ir.IntType(64)
int1 = ir.IntType(1)
void_type = ir.VoidType()
registers, functions, uniques, extracts = {}, {}, {}, {}
memory = {}
loaded = {}
flags = ["ZF", "CF", "OF", "SF"]


def main():
    with open(sys.argv[1], 'r') as xml_file:
        root = ET.parse(xml_file).getroot()
        module = ir.Module(name="lifted")

        for register in root.find('globals').findall('register'):
            if register.get('name') in flags:
                var = ir.GlobalVariable(module, ir.IntType(1), register.get('name'))
                var.initializer = ir.Constant(ir.IntType(1), None)
                var.linkage = 'internal'
                registers[register.get('name')] = var
            elif register.get('name') == "RSP" or register.get('name') == "RIP":
                var = ir.GlobalVariable(module, ir.PointerType(ir.IntType(8)), register.get('name'))
                var.initializer = ir.Constant(ir.PointerType(ir.IntType(8)), None)
                var.linkage = 'internal'
                registers[register.get('name')] = var
            else:
                var = ir.GlobalVariable(module, ir.IntType(8 * int(register.get('size'))), register.get('name'))
                var.initializer = ir.Constant(ir.IntType(8 * int(register.get('size'))), None)
                var.linkage = 'internal'
                registers[register.get('name')] = var
        # for memory_location in root.find('memory').findall('memory'):
        #     var = ir.GlobalVariable(module, ir.IntType(8 * int(memory_location.get('size'))), memory_location.get('name'))
        #     var.initializer = ir.Constant(ir.IntType(8 * int(memory_location.get('size'))), None)
        #     var.linkage = 'internal'
        #     memory[memory_location.get('name')] = var
        for function in root.findall('function'):
            name = function.get('name')
            functions[name] = get_function(function, name, module)
        print(module)
    return 0


def get_function(function, name, module):
    func_return = ir.VoidType()
    fnty = ir.FunctionType(func_return, [])
    ir_func = ir.Function(module, fnty, name)
    builders, blocks = build_cfg(function, ir_func)
    populate_cfg(module, function, builders, blocks)
    return ir_func


def build_cfg(function, ir_func):
    builders, blocks = {}, {}
    block = ir_func.append_basic_block("entry")
    blocks["entry"] = block
    builders["entry"] = ir.IRBuilder(block)
    block = ir_func.append_basic_block("block")
    blocks["block"] = block
    builders["block"] = ir.IRBuilder(block)
    return builders, blocks


def fetch_value(builder, name, flag_op):
    var_type = name.get("storage")
    var_size = int(name.get("size"))*8
    if var_type == "register":
        if name.text in loaded:
            return loaded[name.text]
        else:
            register = registers[name.text]
            loaded[name.text] = builder.load(register)
            return loaded[name.text]
    elif var_type == "constant":
        if flag_op:
            var_size = 1
        var = ir.Constant(ir.IntType(var_size), int(name.text, 0))
        return var
    elif var_type == "unique":
        return uniques[name.text]
    elif var_type == "memory":
        memory_loc = memory[name.text]
        return builder.load(memory_loc)


def get_extract_func(module, smallwidth, bigwidth):
    smallwidth = int(smallwidth) * 8
    bigwidth = int(bigwidth) * 8
    t = (smallwidth, bigwidth)
    if t not in extracts.keys():
        typ = ir.FunctionType(ir.IntType(smallwidth), [ir.IntType(32), ir.IntType(bigwidth)])
        func = ir.Function(module, typ, "ghidra.subpiece.i%.i%d" % (bigwidth, smallwidth))
        func.attributes.add("readnone")
        func.attributes.add("norecurse")
        func.attributes.add("nounwind")
        extracts[t] = func
    return extracts[t]


def fetch_output(builder, name, output):
    var_type = name.get("storage")
    var_size = int(name.get("size"))*8
    if var_type == "register":
        register = registers[name.text]
        builder.store(output, register)
        loaded[name.text] = output
    if var_type == "unique":
        uniques[name.text] = output
    if var_type == "memory":
        memory_loc = memory[name.text]
        builder.store(output, memory_loc)


def getsize(pcode, input_name):
    return int(pcode.find(input_name).get("size")) * 8


def populate_cfg(module, function, builders, blocks):
    if function.get("name") == "main":
        builder = builders["entry"]
        stack_size = 10 * 1024 * 1024
        stack = builder.alloca(ir.IntType(8), stack_size, name="stack")
        stack_top = builder.gep(stack, [ir.Constant(int64, stack_size - 8)], name="stack_top")
        builder.store(stack_top, registers["RSP"])
        builder.branch(blocks["block"])
    builder = builders["block"]
    for instruction in function.find("instructions"):
        for pcode in instruction:
            mnemonic = pcode.find("name")
            flag_op = False
            for child in pcode:
                if child.text in flags:
                    flag_op = True
            if mnemonic.text == "COPY":
                pass
            elif mnemonic.text == "LOAD":
                rsp = builder.load(registers["RSP"])
                rsp2 = builder.gep(rsp, [ir.Constant(int64, int(pcode.find("input_0").text, 0))])
                builder.store(rsp2, registers["RIP"])
            elif mnemonic.text == "STORE":
                pass
            elif mnemonic.text == "BRANCH":
                pass
            elif mnemonic.text == "CBRANCH":
                pass
            elif mnemonic.text == "BRANCHIND":
                pass
            elif mnemonic.text == "CALL":
                pass
            elif mnemonic.text == "CALLIND":
                pass
            elif mnemonic.text == "USERDEFINED":
                pass
            elif mnemonic.text == "RETURN":
                builder.ret_void()
            elif mnemonic.text == "PIECE":
                pass
            elif mnemonic.text == "SUBPIECE":
                lhs = fetch_value(builder, pcode.find("input_0"), flag_op)
                output = builder.trunc(lhs, ir.IntType(int(pcode.find("output").get("size")) * 8))
                fetch_output(builder, pcode.find("output"), output)
            elif mnemonic.text == "INT_EQUAL":
                lhs = fetch_value(builder, pcode.find("input_0"), flag_op)
                rhs = fetch_value(builder, pcode.find("input_1"), flag_op)
                output = builder.icmp_unsigned('==', lhs, rhs)
                fetch_output(builder, pcode.find("output"), output)
            elif mnemonic.text == "INT_NOTEQUAL":
                pass
            elif mnemonic.text == "INT_LESS":
                pass
            elif mnemonic.text == "INT_SLESS":
                lhs = fetch_value(builder, pcode.find("input_0"), flag_op)
                rhs = fetch_value(builder, pcode.find("input_1"), flag_op)
                output = builder.icmp_signed('<', lhs, rhs)
                fetch_output(builder, pcode.find("output"), output)
            elif mnemonic.text == "INT_LESSEQUAL":
                pass
            elif mnemonic.text == "INT_SLESSEQUAL":
                pass
            elif mnemonic.text == "INT_ZEXT":
                lhs = fetch_value(builder, pcode.find("input_0"), flag_op)
                output = builder.zext(lhs, ir.IntType(int(pcode.find("output").get("size")) * 8))
                fetch_output(builder, pcode.find("output"), output)
            elif mnemonic.text == "INT_SEXT":
                pass
            elif mnemonic.text == "INT_ADD":
                if pcode.find("input_0").text == "RSP":
                    rsp = builder.load(registers["RSP"])
                    rsp2 = builder.gep(rsp, [ir.Constant(int64, 8)])
                    builder.store(rsp2, registers["RSP"])
                else:
                    lhs = fetch_value(builder, pcode.find("input_0"), flag_op)
                    rhs = fetch_value(builder, pcode.find("input_1"), flag_op)
                    output = builder.add(lhs, rhs)
                    fetch_output(builder, pcode.find("output"), output)
            elif mnemonic.text == "INT_SUB":
                pass
            elif mnemonic.text == "INT_CARRY":
                flag_op = False
                lhs = fetch_value(builder, pcode.find("input_0"), flag_op)
                rhs = fetch_value(builder, pcode.find("input_1"), flag_op)
                output = builder.uadd_with_overflow(lhs, rhs)
                output = builder.extract_value(output, 1)
                fetch_output(builder, pcode.find("output"), output)
            elif mnemonic.text == "INT_SCARRY":
                flag_op = False
                lhs = fetch_value(builder, pcode.find("input_0"), flag_op)
                rhs = fetch_value(builder, pcode.find("input_1"), flag_op)
                output = builder.sadd_with_overflow(lhs, rhs)
                output = builder.extract_value(output, 1)
                fetch_output(builder, pcode.find("output"), output)
            elif mnemonic.text == "INT_SBORROW":
                pass
            elif mnemonic.text == "INT_2COMP":
                pass
            elif mnemonic.text == "INT_NEGATE":
                pass
            elif mnemonic.text == "INT_XOR":
                pass
            elif mnemonic.text == "INT_AND":
                pass
            elif mnemonic.text == "INT_OR":
                pass
            elif mnemonic.text == "INT_LEFT":
                pass
            elif mnemonic.text == "INT_RIGHT":
                pass
            elif mnemonic.text == "INT_SRIGHT":
                pass
            elif mnemonic.text == "INT_MULT":
                lhs = fetch_value(builder, pcode.find("input_0"), flag_op)
                rhs = fetch_value(builder, pcode.find("input_1"), flag_op)
                output = builder.mul(lhs, rhs)
                fetch_output(builder, pcode.find("output"), output)
            elif mnemonic.text == "INT_DIV":
                pass
            elif mnemonic.text == "INT_REM":
                pass
            elif mnemonic.text == "INT_SDIV":
                pass
            elif mnemonic.text == "INT_SREM":
                pass
            elif mnemonic.text == "BOOL_NEGATE":
                pass
            elif mnemonic.text == "BOOL_XOR":
                pass
            elif mnemonic.text == "BOOL_AND":
                pass
            elif mnemonic.text == "BOOL_OR":
                pass
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


if __name__ == "__main__":
    main()

