from llvmlite import ir
import xml.etree.ElementTree as ET

int32 = ir.IntType(32)
int64 = ir.IntType(64)
int1 = ir.IntType(1)
void_type = ir.VoidType()
registers, varnodes, functions = {}, {}, {}


def main():
    root = ET.parse('/tmp/output.xml').getroot()
    module = ir.Module(name="lifted")
    for register in root.find('globals').findall('register'):
        var = ir.GlobalVariable(module, ir.IntType(8*int(register.get('size'))), register.get('name'))
        var.initializer = ir.Constant(ir.IntType(8*int(register.get('size'))), None)
        var.linkage = 'internal'
        registers[register.get('name')] = var
    for function in root.findall('function'):
        name = function.get('name')
        functions[name] = get_function(function, name, module)
    print(module)
    return 0


def get_function(function, name, module):
    if name == "main":
        # add stuff
        pass
    func_return = get_function_output(function)
    params, j = get_function_inputs(function)
    fnty = ir.FunctionType(func_return, params)
    ir_func = ir.Function(module, fnty, name)
    for x in range(0, j):
        name = function.get("inputStorage_" + str(x)).split(":")[0]
        ir_func.args[x].name = name
        if name not in varnodes:
            varnodes[name] = ir_func.args[x]
    builders, blocks = build_cfg(function, ir_func)
    populate_cfg(module, function, builders, blocks)
    return ir_func


def build_cfg(function, ir_func):
    builders, blocks = [], {}
    block = ir_func.append_basic_block(name="entry")
    blocks["entry"] = block
    builder = ir.IRBuilder(block)
    builders.append(builder)
    for bb in function:
        block = ir_func.append_basic_block(name=bb.get('start'))
        blocks[bb.get('start')] = block
        builder = ir.IRBuilder(block)
        builders.append(builder)
    return builders, blocks


def get_function_inputs(function):
    params, inputs, i, j = [], "inputStorage_", 0, 0
    while function.get(inputs + str(i)) is not None:
        input_type = function.get("inputType_" + str(i))
        if input_type == "int":
            params.append(ir.IntType(int(function.get("inputTypeLength_" + str(i)))))
            j += 1
        i += 1
    return params, j


def get_function_output(function):
    return_type = function.get('outputType')
    if return_type == "int":
        func_return = int32
    elif return_type == "ulong":
        func_return = int64
    else:
        func_return = void_type
    return func_return


def fetch_value(builder, module, name):
    var_type = name.get("storage")
    var_size = int(name.get("size"))*8
    if var_type == "register":
        if name.text not in registers.keys():
            var = ir.GlobalVariable(module, ir.IntType(var_size), name.text)
            registers[name.text] = var
        return builder.load(registers[name.text])
    elif var_type == "constant":
        var = ir.Constant(ir.IntType(var_size), int(name.text, 0))
        return var
    elif var_type == "unique":
        if name.text not in registers.keys():
            var = ir.GlobalVariable(module, ir.IntType(var_size), name.text)
            registers[name.text] = var
        return builder.load(registers[name.text])


def fetch_output(builder, module, name, output):
    var_type = name.get("storage")
    var_size = int(name.get("size"))*8
    if var_type == "register":
        if name.text not in registers.keys():
            var = ir.GlobalVariable(module, ir.IntType(var_size), name.text)
            registers[name.text] = var
        builder.store(output, registers[name.text])
    if var_type == "unique":
        if name.text not in registers.keys():
            var = ir.GlobalVariable(module, ir.IntType(var_size), name.text)
            registers[name.text] = var
        builder.store(output, registers[name.text])


def getsize(pcode, input_name):
    return int(pcode.find(input_name).get("size")) * 8


def populate_cfg(module, function, builders, blocks):
    builder = builders[0]
    if function.get("name") == "main":
        stack = builder.alloca(ir.IntType(8), 10 * 1024 * 1024, name = "stack")
        stack_top = builder.gep(stack, [ir.Constant (int64, 10 * 1024 * 1024 - 8)], name="stack_top")
    builder.branch(blocks[function.find("BB_0").get("start")])
    i = 1
    for block in function:
        builder = builders[i]
        i += 1
        for pcode in block:
            mnemonic = pcode.find("name")
            if mnemonic.text == "COPY":
                output = fetch_value(builder, module, pcode.find("input_0"))
                fetch_output(builder, module, pcode.find("output"), output)
            elif mnemonic.text == "LOAD":
                pass
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
                pass
            elif mnemonic.text == "INT_EQUAL":
                pass
            elif mnemonic.text == "INT_NOTEQUAL":
                pass
            elif mnemonic.text == "INT_LESS":
                pass
            elif mnemonic.text == "INT_SLESS":
                pass
            elif mnemonic.text == "INT_LESSEQUAL":
                pass
            elif mnemonic.text == "INT_SLESSEQUAL":
                pass
            elif mnemonic.text == "INT_ZEXT":
                lhs = fetch_value(builder, module, pcode.find("input_0"))
                new_size = ir.IntType(getsize(pcode, "output"))
                output = builder.zext(lhs, new_size)
                fetch_output(builder, module, pcode.find("output"), output)
            elif mnemonic.text == "INT_SEXT":
                pass
            elif mnemonic.text == "INT_ADD":
                lhs = fetch_value(builder, module, pcode.find("input_0"))
                rhs = fetch_value(builder, module, pcode.find("input_1"))
                output = builder.add(lhs, rhs)
                fetch_output(builder, module, pcode.find("output"), output)
            elif mnemonic.text == "INT_SUB":
                lhs = fetch_value(builder, module, pcode.find("input_0"))
                rhs = fetch_value(builder, module, pcode.find("input_1"))
                output = builder.sub(lhs, rhs)
                fetch_output(builder, module, pcode.find("output"), output)
            elif mnemonic.text == "INT_CARRY":
                pass
            elif mnemonic.text == "INT_SCARRY":
                pass
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
                lhs = fetch_value(builder, module, pcode.find("input_0"))
                rhs = fetch_value(builder, module, pcode.find("input_1"))
                output = builder.mul(lhs, rhs)
                fetch_output(builder, module, pcode.find("output"), output)
            elif mnemonic.text == "INT_DIV":
                lhs = fetch_value(builder, module, pcode.find("input_0"))
                rhs = fetch_value(builder, module, pcode.find("input_1"))
                output = builder.div(lhs, rhs)
                fetch_output(builder, module, pcode.find("output"), output)
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
                output = fetch_value(builder, module, pcode.find("input_0"))
                fetch_output(builder, module, pcode.find("output"), output)
            else:
                raise Exception("Not a standard pcode instruction")


if __name__ == "__main__":
    main()

