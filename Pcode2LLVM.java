//@author Tejvinder Singh Toor
//@category
//@keybinding
//@menupath
//@toolbar
//EXAMPLE: analyzeHeadless ~/github/thesis/samples thesis.gpr -process fib -postScript HighFunction_Analysis.java -scriptlog ~/Desktop/GhidraProjects/script.log


import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Attr;

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

import java.io.File;


public class Pcode2LLVM extends HeadlessScript {

    @Override
    protected void run() throws Exception {

        DocumentBuilderFactory dFactory = DocumentBuilderFactory.newInstance();
        DocumentBuilder dBuilder = dFactory.newDocumentBuilder();
        Document doc = dBuilder.newDocument();

        // program element
        Element rootElement = doc.createElement("program");
        doc.appendChild(rootElement);

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

            // function element
            Element functionElement = doc.createElement("function");
            rootElement.appendChild(functionElement);
            Attr fnameAttr = doc.createAttribute("name");
            fnameAttr.setValue(func.getName());
            functionElement.setAttributeNode(fnameAttr);

            DecompileResults results = ifc.decompileFunction(func, 300, null);
            HighFunction high = results.getHighFunction();
            Element foutputElement = doc.createElement("output");
            functionElement.appendChild(foutputElement);
            Attr foutputAttr = doc.createAttribute("type");
            if (!func.hasNoReturn()) {
                foutputAttr.setValue(func.getReturnType().getDisplayName());
            } else {
                foutputAttr.setValue("void");
            }
            foutputElement.setAttributeNode(foutputAttr);

            for (int x = 0; x < func.getParameterCount(); x++) {
                Element fInputElement = doc.createElement("input");
                functionElement.appendChild(fInputElement);
                Attr fInputTypeAttr = doc.createAttribute("type");
                fInputTypeAttr.setValue(func.getParameter(x).getDataType().getDisplayName());
                fInputElement.setAttributeNode(fInputTypeAttr);
                Attr fInputNameAttr = doc.createAttribute("name");
                fInputNameAttr.setValue(func.getParameter(x).getName());
                fInputElement.setAttributeNode(fInputNameAttr);
            }
            Address entry = func.getEntryPoint();
            InstructionIterator ii = listing.getInstructions(entry, true);
            int y = 0;
            while (ii.hasNext()) {
                Instruction inst = ii.next();
                PcodeOp[] pcode = inst.getPcode();
                Element instructionElement = doc.createElement("instruction_" + y);
                functionElement.appendChild(instructionElement);
                for (int i = 0; i < pcode.length; i++) {
                    Element pcodeElement = doc.createElement("pcode_" + i);
                    instructionElement.appendChild(pcodeElement);
                    Varnode vnodeOutput = pcode[i].getOutput();
                    if (vnodeOutput != null) {
                        Element iOutputElement = doc.createElement("output");
                        pcodeElement.appendChild(iOutputElement);
                        iOutputElement.appendChild(doc.createTextNode(vnodeOutput.toString(language)));
                        Attr size = doc.createAttribute("size");
                        size.setValue(String.valueOf(vnodeOutput.getSize()));
                        iOutputElement.setAttributeNode(size);

                    }
                    Element iNameElement = doc.createElement("name");
                    pcodeElement.appendChild(iNameElement);
                    iNameElement.appendChild(doc.createTextNode(pcode[i].getMnemonic()));
                    for (int j = 0; j < pcode[i].getNumInputs(); j++) {
                        Element iInputElement = doc.createElement("input_" + j);
                        pcodeElement.appendChild(iInputElement);
                        iInputElement.appendChild(doc.createTextNode(pcode[i].getInput(j).toString(language)));
                        Attr size = doc.createAttribute("size");
                        size.setValue(String.valueOf(pcode[i].getInput(j).getSize()));
                        iInputElement.setAttributeNode(size);
                    }
                }
                y++;
            }
        }
        // write the content into xml file
        TransformerFactory transformerFactory = TransformerFactory.newInstance();
        Transformer transformer = transformerFactory.newTransformer();
        DOMSource source = new DOMSource(doc);
        StreamResult result = new StreamResult(new File("/tmp/output.xml"));
        transformer.transform(source, result);

        // Output to console for testing
        StreamResult consoleResult = new StreamResult(System.out);
        transformer.transform(source, consoleResult);
    }
}
