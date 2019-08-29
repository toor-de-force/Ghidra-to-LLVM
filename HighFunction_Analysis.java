//
//@author Tejvinder Singh Toor
//@category 
//@keybinding
//@menupath
//@toolbar
//EXAMPLE: analyzeHeadless *path to project file* *project file* -process *file* -postScript HighFunction_Analysis.java

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileWriter;
import java.io.PrintWriter;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.util.headless.HeadlessScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.lang.Language;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;

public class HighFunction_Analysis extends HeadlessScript {

	@Override
	protected void run() throws Exception {
		
		File outputFile = new File( "/tmp/result.txt");
		outputFile.createNewFile();
		FileWriter pw = new FileWriter(outputFile);
		
		DecompileOptions options = new DecompileOptions();
		DecompInterface ifc = new DecompInterface();
		ifc.setOptions(options);
		ifc.setSimplificationStyle("decompile");
		
        Language language = currentProgram.getLanguage();
        AddressSetView set = currentProgram.getMemory().getExecuteSet();
		Listing listing = currentProgram.getListing();
		FunctionIterator fi = listing.getFunctions(true);
		Function func = null;
		
		while (fi.hasNext()) {
			func = fi.next();
			DecompileResults results = ifc.decompileFunction(func, 300, null);
			HighFunction high = results.getHighFunction();
			if (func.hasNoReturn()) {
				pw.write("\nvoid " + func.getName() + "(");
			} else {
				pw.write("\n" + func.getReturnType().getDisplayName() + " " + func.getName() + "(");
			}
			for (int x = 0; x < func.getParameterCount(); x++) {
				if (x == 0) {
					pw.write(func.getParameter(x).getName());
				} else {
					pw.write(", " + func.getParameter(x).getName());
				}
			}
			pw.write("):\n");
			Address entry = func.getEntryPoint();
			InstructionIterator ii = listing.getInstructions(entry, true);
			while (ii.hasNext()) {
				Instruction inst = ii.next();
	            PcodeOp[] pcode = inst.getPcode();
	            for (int i = 0; i < pcode.length; i++) {
	            	String printer = "\t";
	            	Varnode vnodeOutput = pcode[i].getOutput();
	            	if (vnodeOutput != null) {
	            		printer = printer + vnodeOutput.toString(language) + " = "; 
	            	}
	            	printer = printer + pcode[i].getMnemonic() + "(";
	            	for (int j = 0; j < pcode[i].getNumInputs(); j++) {
	            		if (j == 0) {
	            			printer = printer + pcode[i].getInput(j).toString(language);
	            		} else {
	            			printer = printer + ", " + pcode[i].getInput(j).toString(language);
	            		}
	            		
	            	}
	                pw.write(printer + ");\n");
	            }	
			}
		}
		pw.close();		
	}
}
