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
  
### 2. Edit g2llvm.py

The script requires you to provide the location of two files (absolute path):
- ghidra_headless_loc = "/PATH/TO/ghidra_9.1.1_PUBLIC/support/analyzeHeadless"
- prj_dir = "/PATH/TO/GhidraProjects/"

## Usage
To run the the tool, simply run the g2llvm.py script. It takes a single mandatory argument, the target executable.

Optional arguments:

- '-out' emits intermediate files
- '-opt X' attempts to optimize the file. Valid options 0-3. (Currently only 0 works)
- '-cfg' saves a .PNG of the whole module CFG.


###### Extra Scripts

- HighFunction_Analysis.java: Prints readable version of high function representation
- HighFunction2LLVM.java: Makes an XML file if the high function representation

###### TODO

- Implement lifting using Ghidra's HighFunction (will eventually be the default)

