from llvmlite import ir
import xml.etree.ElementTree as ET

int32 = ir.IntType(32)
int64 = ir.IntType(64)
int1 = ir.IntType(1)
void_type = ir.VoidType()


def main():
    root = ET.parse('/tmp/output.xml').getroot()
    module = ir.Module(name="lifted")
    functions = {}

    for function in root.findall('function'):
        name = function.get('name')
        return_type = function.get('outputType')
        if return_type == "int":
            func_return = int32
        elif return_type == "ulong":
            func_return = int64
        else:
            func_return = void_type
        params = []
        vars = {}
        inputs, i, j = "inputStorage_", 0, 0
        while function.get(inputs + str(i)) is not None:
            input_type = function.get("inputType_" + str(i))
            if input_type == "int":
                params.append(ir.IntType(int(function.get("inputTypeLength_" + str(i)))))
                j += 1
            i += 1
        fnty = ir.FunctionType(func_return, params)
        ir_func = ir.Function(module, fnty, name)
        for x in range(0, j):
            name = function.get("inputStorage_" + str(x)).split(":")[0]
            ir_func.args[x].name = name
            vars[name] = ir_func.args[x]
        functions[name] = ir_func

        # building CFG
        builders, blocks = [], {}
        for bb in function:
            block = ir_func.append_basic_block(name=bb.get('start'))
            blocks[bb.get('start')] = block
            builder = ir.IRBuilder(block)
            builders.append(builder)

        # populating bb's with instructions
        i = 0
        for block in function:
            builder = builders[i]
            i += 1
            for pcode in block:
                child = pcode.find("name")
                if child.text == "COPY":
                    ptr = builder.alloca(ir.IntType(getsize(pcode, "output")), name=pcode.find("output").text)
                    builder.store(fetch_integer(pcode, "input_0", getsize(pcode, "input_0")), ptr)
                elif child.text == "LOAD":
                    offset = pcode.find('input_0')
                    if offset is None:
                        print("LOAD WITHOUT INPUT 0")
                    else:
                        ptr = ir.Constant(ir.PointerType(int32), pcode.find("input_0"))
                        builder.load(ptr, align=0)
                elif child.text == "STORE":
                    pass
                elif child.text == "BRANCH":
                    target = pcode.find("input_0").text[2:-2]
                    builder.branch(blocks[target])
                elif child.text == "CBRANCH":
                    true_br = pcode.find("input_0").text[2:-2]
                    false_br = str(hex(int(block.get('end'), 16) + 0x2))[2:]
                    while len(false_br) < 8:
                        false_br = "0" + false_br
                    conditional = pcode.find("input_1").text
                    # This is wrong
                    if conditional != "0":
                        conditional = 1
                    else:
                        conditional = 0
                    builder.cbranch(ir.Constant(int1, conditional), blocks[true_br], blocks[false_br])
                elif child.text == "BRANCHIND":
                    # Need to test this with example
                    target = pcode.find("input_0").text[2:-2]
                    builder.branch(blocks[target])
                elif child.text == "CALL":
                    pass
                elif child.text == "CALLIND":
                    pass
                elif child.text == "USERDEFINED":
                    pass
                elif child.text == "RETURN":
                    returning = pcode.find('input_1')
                    if returning is None:
                        builder.ret_void()
                    else:
                        builder.ret(fetch_integer(pcode, "input_1", getsize(pcode, "input_1")))
                elif child.text == "PIECE":
                    pass
                elif child.text == "SUBPIECE":
                    pass
                elif child.text == "INT_EQUAL":
                    lhs = fetch_integer(pcode, "input_0", getsize(pcode, "input_0"))
                    rhs = fetch_integer(pcode, "input_1", getsize(pcode, "input_1"))
                    res = pcode.find("output").text
                    builder.icmp_unsigned('==', lhs, rhs, res)
                elif child.text == "INT_NOTEQUAL":
                    lhs = fetch_integer(pcode, "input_0", getsize(pcode, "input_0"))
                    rhs = fetch_integer(pcode, "input_1", getsize(pcode, "input_1"))
                    res = pcode.find("output").text
                    builder.icmp_unsigned('!=', lhs, rhs, res)
                elif child.text == "INT_LESS":
                    lhs = fetch_integer(pcode, "input_0", getsize(pcode, "input_0"))
                    rhs = fetch_integer(pcode, "input_1", getsize(pcode, "input_1"))
                    res = pcode.find("output").text
                    builder.icmp_unsigned('<', lhs, rhs, res)
                elif child.text == "INT_SLESS":
                    lhs = fetch_integer(pcode, "input_0", getsize(pcode, "input_0"))
                    rhs = fetch_integer(pcode, "input_1", getsize(pcode, "input_1"))
                    res = pcode.find("output").text
                    builder.icmp_signed('<', lhs, rhs, res)
                elif child.text == "INT_LESSEQUAL":
                    lhs = fetch_integer(pcode, "input_0", getsize(pcode, "input_0"))
                    rhs = fetch_integer(pcode, "input_1", getsize(pcode, "input_1"))
                    res = pcode.find("output").text
                    builder.icmp_unsigned('<=', lhs, rhs, res)
                elif child.text == "INT_SLESSEQUAL":
                    lhs = fetch_integer(pcode, "input_0", getsize(pcode, "input_0"))
                    rhs = fetch_integer(pcode, "input_1", getsize(pcode, "input_1"))
                    res = pcode.find("output").text
                    builder.icmp_signed('<=', lhs, rhs, res)
                elif child.text == "INT_ZEXT":
                    lhs = fetch_integer(pcode, "input_0", getsize(pcode, "input_0"))
                    new_size = ir.IntType(getsize(pcode, "output"))
                    builder.zext(lhs, new_size, pcode.find("output").text)
                elif child.text == "INT_SEXT":
                    lhs = fetch_integer(pcode, "input_0", getsize(pcode, "input_0"))
                    new_size = ir.IntType(getsize(pcode, "output"))
                    builder.sext(lhs, new_size)
                elif child.text == "INT_ADD":
                    lhs = fetch_integer(pcode, "input_0", getsize(pcode, "input_0"))
                    rhs = fetch_integer(pcode, "input_1", getsize(pcode, "input_1"))
                    res = pcode.find("output").text
                    builder.add(lhs, rhs, res)
                elif child.text == "INT_SUB":
                    lhs = fetch_integer(pcode, "input_0", getsize(pcode, "input_0"))
                    rhs = fetch_integer(pcode, "input_1", getsize(pcode, "input_1"))
                    res = pcode.find("output").text
                    builder.sub(lhs, rhs, res)
                elif child.text == "INT_CARRY":
                    lhs = fetch_integer(pcode, "input_0", getsize(pcode, "input_0"))
                    rhs = fetch_integer(pcode, "input_1", getsize(pcode, "input_1"))
                    res = pcode.find("output").text
                    builder.uadd_with_overflow(lhs, rhs, res)
                elif child.text == "INT_SCARRY":
                    lhs = fetch_integer(pcode, "input_0", getsize(pcode, "input_0"))
                    rhs = fetch_integer(pcode, "input_1", getsize(pcode, "input_1"))
                    res = pcode.find("output").text
                    builder.sadd_with_overflow(lhs, rhs, res)
                elif child.text == "INT_SBORROW":
                    lhs = fetch_integer(pcode, "input_0", getsize(pcode, "input_0"))
                    rhs = fetch_integer(pcode, "input_1", getsize(pcode, "input_1"))
                    res = pcode.find("output").text
                    builder.ssub_with_overflow(lhs, rhs, res)
                elif child.text == "INT_2COMP":
                    lhs = fetch_integer(pcode, "input_0", getsize(pcode, "input_0"))
                    res = pcode.find("output").text
                    builder.neg(lhs, res)
                elif child.text == "INT_NEGATE":
                    lhs = fetch_integer(pcode, "input_0", getsize(pcode, "input_0"))
                    res = pcode.find("output").text
                    builder.not_(lhs, res)
                elif child.text == "INT_XOR":
                    lhs = fetch_integer(pcode, "input_0", getsize(pcode, "input_0"))
                    rhs = fetch_integer(pcode, "input_1", getsize(pcode, "input_1"))
                    res = pcode.find("output").text
                    builder.xor(lhs, rhs, res)
                elif child.text == "INT_AND":
                    lhs = fetch_integer(pcode, "input_0", getsize(pcode, "input_0"))
                    rhs = fetch_integer(pcode, "input_1", getsize(pcode, "input_1"))
                    res = pcode.find("output").text
                    builder.and_(lhs, rhs, res)
                elif child.text == "INT_OR":
                    lhs = fetch_integer(pcode, "input_0", getsize(pcode, "input_0"))
                    rhs = fetch_integer(pcode, "input_1", getsize(pcode, "input_1"))
                    res = pcode.find("output").text
                    builder.or_(lhs, rhs, res)
                elif child.text == "INT_LEFT":
                    lhs = fetch_integer(pcode, "input_0", getsize(pcode, "input_0"))
                    rhs = fetch_integer(pcode, "input_1", getsize(pcode, "input_1"))
                    res = pcode.find("output").text
                    builder.shl(lhs, rhs, res)
                elif child.text == "INT_RIGHT":
                    lhs = fetch_integer(pcode, "input_0", getsize(pcode, "input_0"))
                    rhs = fetch_integer(pcode, "input_1", getsize(pcode, "input_1"))
                    res = pcode.find("output").text
                    builder.lshr(lhs, rhs, res)
                elif child.text == "INT_SRIGHT":
                    lhs_size = getsize(pcode, "input_0")
                    lhs = fetch_integer(pcode, "input_0", lhs_size)
                    rhs_size = getsize(pcode, "input_1")
                    # This is a hack because pcode does not check size while llvm does for shifts.
                    if rhs_size < lhs_size:
                        rhs_size = lhs_size
                    rhs = fetch_integer(pcode, "input_1", rhs_size)
                    res = pcode.find("output").text
                    builder.ashr(lhs, rhs, res)
                elif child.text == "INT_MULT":
                    lhs = fetch_integer(pcode, "input_0", getsize(pcode, "input_0"))
                    rhs = fetch_integer(pcode, "input_1", getsize(pcode, "input_1"))
                    res = pcode.find("output").text
                    builder.mul(lhs, rhs, res)
                elif child.text == "INT_DIV":
                    lhs = fetch_integer(pcode, "input_0", getsize(pcode, "input_0"))
                    rhs = fetch_integer(pcode, "input_1", getsize(pcode, "input_1"))
                    res = pcode.find("output").text
                    builder.udiv(lhs, rhs, res)
                elif child.text == "INT_REM":
                    lhs = fetch_integer(pcode, "input_0", getsize(pcode, "input_0"))
                    rhs = fetch_integer(pcode, "input_1", getsize(pcode, "input_1"))
                    res = pcode.find("output").text
                    builder.urem(lhs, rhs, res)
                elif child.text == "INT_SDIV":
                    lhs = fetch_integer(pcode, "input_0", getsize(pcode, "input_0"))
                    rhs = fetch_integer(pcode, "input_1", getsize(pcode, "input_1"))
                    res = pcode.find("output").text
                    builder.sdiv(lhs, rhs, res)
                elif child.text == "INT_SREM":
                    lhs = fetch_integer(pcode, "input_0", getsize(pcode, "input_0"))
                    rhs = fetch_integer(pcode, "input_1", getsize(pcode, "input_1"))
                    res = pcode.find("output").text
                    builder.srem(lhs, rhs, res)
                elif child.text == "BOOL_NEGATE":
                    lhs = fetch_integer(pcode, "input_0", getsize(pcode, "input_0"))
                    res = pcode.find("output").text
                    builder.not_(lhs, res)
                elif child.text == "BOOL_XOR":
                    lhs = fetch_integer(pcode, "input_0", getsize(pcode, "input_0"))
                    rhs = fetch_integer(pcode, "input_1", getsize(pcode, "input_1"))
                    res = pcode.find("output").text
                    builder.xor(lhs, rhs, res)
                elif child.text == "BOOL_AND":
                    lhs = fetch_integer(pcode, "input_0", getsize(pcode, "input_0"))
                    rhs = fetch_integer(pcode, "input_1", getsize(pcode, "input_1"))
                    res = pcode.find("output").text
                    builder.and_(lhs, rhs, res)
                elif child.text == "BOOL_OR":
                    lhs = fetch_integer(pcode, "input_0", getsize(pcode, "input_0"))
                    rhs = fetch_integer(pcode, "input_1", getsize(pcode, "input_1"))
                    res = pcode.find("output").text
                    builder.or_(lhs, rhs, res)
                elif child.text == "FLOAT_EQUAL":
                    lhs = fetch_fp(pcode, "input_0")
                    rhs = fetch_fp(pcode, "input_1")
                    res = pcode.find("output").text
                    builder.fcmp_ordered('==', lhs, rhs, res)
                elif child.text == "FLOAT_NOTEQUAL":
                    lhs = fetch_fp(pcode, "input_0")
                    rhs = fetch_fp(pcode, "input_1")
                    res = pcode.find("output").text
                    builder.fcmp_ordered('!=', lhs, rhs, res)
                elif child.text == "FLOAT_LESS":
                    lhs = fetch_fp(pcode, "input_0")
                    rhs = fetch_fp(pcode, "input_1")
                    res = pcode.find("output").text
                    builder.fcmp_ordered('<', lhs, rhs, res)
                elif child.text == "FLOAT_LESSEQUAL":
                    lhs = fetch_fp(pcode, "input_0")
                    rhs = fetch_fp(pcode, "input_1")
                    res = pcode.find("output").text
                    builder.fcmp_ordered('<=', lhs, rhs, res)
                elif child.text == "FLOAT_ADD":
                    lhs = fetch_fp(pcode, "input_0")
                    rhs = fetch_fp(pcode, "input_1")
                    res = pcode.find("output").text
                    builder.fadd(lhs, rhs, res)
                elif child.text == "FLOAT_SUB":
                    lhs = fetch_fp(pcode, "input_0")
                    rhs = fetch_fp(pcode, "input_1")
                    res = pcode.find("output").text
                    builder.fsub(lhs, rhs, res)
                elif child.text == "FLOAT_MULT":
                    lhs = fetch_fp(pcode, "input_0")
                    rhs = fetch_fp(pcode, "input_1")
                    res = pcode.find("output").text
                    builder.fmul(lhs, rhs, res)
                elif child.text == "FLOAT_DIV":
                    lhs = fetch_fp(pcode, "input_0")
                    rhs = fetch_fp(pcode, "input_1")
                    res = pcode.find("output").text
                    builder.fdiv(lhs, rhs, res)
                elif child.text == "FLOAT_NEG":
                    lhs = fetch_fp(pcode, "input_0")
                    res = pcode.find("output").text
                    builder.call("fneg", lhs, res)
                elif child.text == "FLOAT_ABS":
                    lhs = fetch_fp(pcode, "input_0")
                    res = pcode.find("output").text
                    builder.call("fabs", lhs, res)
                elif child.text == "FLOAT_SQRT":
                    lhs = fetch_fp(pcode, "input_0")
                    res = pcode.find("output").text
                    builder.call("llvm.sqrt", lhs, res)
                elif child.text == "FLOAT_CEIL":
                    lhs = fetch_fp(pcode, "input_0")
                    res = pcode.find("output").text
                    builder.call("llvm.ceil", lhs, res)
                elif child.text == "FLOAT_FLOOR":
                    lhs = fetch_fp(pcode, "input_0")
                    res = pcode.find("output").text
                    builder.call("llvm.floor", lhs, res)
                elif child.text == "FLOAT_ROUND":
                    lhs = fetch_fp(pcode, "input_0")
                    res = pcode.find("output").text
                    builder.call("llvm.round", lhs, res)
                elif child.text == "FLOAT_NAN":
                    lhs = fetch_fp(pcode, "input_0")
                    res = pcode.find("output").text
                    builder.fcmp_unordered("uno", lhs, lhs, res)
                elif child.text == "INT2FLOAT":
                    lhs = fetch_fp(pcode, "input_0")
                    res = pcode.find("output").text
                    builder.sitofp(lhs, res)
                elif child.text == "FLOAT2FLOAT":
                    if getsize(pcode, "output") > getsize(pcode, "input_0"):
                        builder.fpext(fetch_fp(pcode, "input_0"), ir.FloatType())
                    else:
                        builder.fptrunc(fetch_fp(pcode, "input_0"), ir.FloatType())
                elif child.text == "TRUNC":
                    lhs = fetch_fp(pcode, "input_0")
                    builder.fptosi(lhs, ir.IntType(getsize(pcode, "output")))
                elif child.text == "CPOOLREF":
                    # object oriented
                    pass
                elif child.text == "NEW":
                    # object oriented
                    pass
                elif child.text == "MULTIEQUAL":
                    phi = builder.phi(ir.IntType(getsize(pcode, "output")))
                    inputs_exist, j = True, 0
                    while inputs_exist:
                        target = "input_" + str(j)
                        text = pcode.find("in_" + str(j))
                        if text is None:
                            inputs_exist = False
                        else:
                            phi.add_incoming(fetch_integer(pcode, target, getsize(pcode, target)), blocks[0])
                        j += 1
                    pass
                elif child.text == "INDIRECT":
                    pass
                elif child.text == "PTRADD":
                    pass
                elif child.text == "PTRSUB":
                    pass
                elif child.text == "CAST":
                    pass
                else:
                    print("Not a standard pcode instruction")

    print(module)
    return 0


def fetch_integer(pcode, input_name, size):
    return ir.Constant(ir.IntType(size), pcode.find(input_name).text)


def fetch_fp(pcode, input_name):
    return ir.Constant(ir.FloatType(), pcode.find(input_name).text)


def getsize(pcode, input_name):
    return int(pcode.find(input_name).get("size")) * 8


# def fetch_value(pcode, input_name):
#     if input_name not in varnodes:
#         varnodes[input_name] = ir.Value
#     return varnodes.get(input_name)


if __name__ == "__main__":
    main()

