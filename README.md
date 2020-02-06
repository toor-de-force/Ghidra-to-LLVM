# Ghidra-to-LLVM
This tool lifts a a compiled binary to LLVM.

## Required packages for Python 3
- llvmlite
- graphviz

## Installation Instructions (Linux Only)

### 1. Install Ghidra

https://ghidra-sre.org/ghidra_9.1.1_PUBLIC_20191218.zip

- Extract the JDK: tar xvf <JDK distribution .tar.gz>
- Open ~/.bashrc with an editor of your choice. For example:vi ~/.bashrc
- At the very end of the file, add the JDK bin directory to the PATH variable:export PATH=<path of extracted JDK dir>/bin:$PATH
- Save file
- Restart any open terminal windows for changes to take effect

###### Extra Scripts

- HighFunction_Analysis.java: Prints readable version of high function representation
- HighFunction2LLVM.java: Makes an XML file if the high function representation
