from llvmlite import ir
import xml.etree.ElementTree as ET

int32 = ir.IntType(32)
int1 = ir.IntType(1)


def main():
    root = ET.parse('/tmp/output.xml').getroot()
    module = ir.Module(name="recovered")

    void_type = ir.VoidType()
    fnty = ir.FunctionType(void_type, [])

    for function in root.findall('function'):
        name = function.get('name')
        if name == "addtwo" or name == "main":
            ir_func = ir.Function(module, fnty, name)
            block = ir_func.append_basic_block(name="entry")
            builder = ir.IRBuilder(block)
            for instruction in function:
                for pcode in instruction:
                    child = pcode.find("name")
                    if child.text == "COPY":
                        pass
                    elif child.text == "LOAD":
                        pass
                    elif child.text == "STORE":
                        pass
                    elif child.text == "BRANCH":
                        pass
                    elif child.text == "CBRANCH":
                        pass
                    elif child.text == "BRANCHIND":
                        pass
                    elif child.text == "CALL":
                        pass
                    elif child.text == "CALLIND":
                        pass
                    elif child.text == "USERDEFINED":
                        pass
                    elif child.text == "RETURN":
                        pass
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
                        builder.zext(lhs, new_size)
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
                        pass
                    elif child.text == "TRUNC":
                        pass
                    elif child.text == "CPOOLREF":
                        pass
                    elif child.text == "NEW":
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


if __name__ == "__main__":
    main()
