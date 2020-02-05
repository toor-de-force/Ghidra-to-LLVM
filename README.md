# Ghidra-to-LLVM
**THIS IS A WORK IN PROGRESS, NOT READY**

Current rough path is through the java plugin in Ghidra which produces an XML file of pcode ops, and then through the python file to generate LLVM bitcode via LLVMlite.

###### Extra Scripts

- HighFunction_Analysis.java: Prints readable version of high function representation
- HighFunction2LLVM.java: Makes an XML file if the high function representation
