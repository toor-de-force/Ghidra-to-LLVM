//@author Tejvinder Singh Toor
//@category
//@keybinding
//@menupath
//@toolbar
//EXAMPLE: analyzeHeadless ~/github/thesis/samples thesis.gpr -process fib -postScript Pcode2LLVM.java -scriptlog ~/Desktop/GhidraProjects/script.log


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
import java.util.ArrayList;
import java.util.List;


public class GhidraToXML extends HeadlessScript {

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

        Element globals = doc.createElement("globals");
        rootElement.appendChild(globals);
        Element memory = doc.createElement("memory");
        rootElement.appendChild(memory);
        ArrayList<String> registerList = new ArrayList<>();
        ArrayList<String> registerSize = new ArrayList<>();

        ArrayList<String> memoryList = new ArrayList<>();
        ArrayList<String> memorySize = new ArrayList<>();

        while (fi.hasNext()) {
            func = fi.next();

            // function element
            Element functionElement = doc.createElement("function");
            rootElement.appendChild(functionElement);
            Attr fnameAttr = doc.createAttribute("name");
            fnameAttr.setValue(func.getName());
            functionElement.setAttributeNode(fnameAttr);

            Attr fAddress = doc.createAttribute("address");
            fAddress.setValue(func.getEntryPoint().toString());
            functionElement.setAttributeNode(fAddress);

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
            Element instructions = doc.createElement("instructions");
            functionElement.appendChild(instructions);
            while (ii.hasNext()) {
                Instruction inst = ii.next();
                PcodeOp[] pcode = inst.getPcode();
                Element instructionElement = doc.createElement("instruction_" + y);
                instructions.appendChild(instructionElement);

                Element address = doc.createElement("address");
                instructionElement.appendChild(address);
                address.appendChild(doc.createTextNode(inst.getAddress().toString()));

                Element pcodes = doc.createElement("pcodes");
                instructionElement.appendChild(pcodes);
                for (int i = 0; i < pcode.length; i++) {
                    Element pcodeElement = doc.createElement("pcode_" + i);
                    pcodes.appendChild(pcodeElement);
                    Varnode vnodeOutput = pcode[i].getOutput();
                    if (vnodeOutput != null) {
                        Element pOutputElement = doc.createElement("output");
                        pcodeElement.appendChild(pOutputElement);
                        pOutputElement.appendChild(doc.createTextNode(vnodeOutput.toString(language)));
                        Attr size = doc.createAttribute("size");
                        size.setValue(String.valueOf(vnodeOutput.getSize()));
                        pOutputElement.setAttributeNode(size);
                        Attr outIsRegister = doc.createAttribute("storage");
                        String storage = "";
                        if (vnodeOutput.isRegister()) {
                            storage = "register";
                            if (!registerList.contains(vnodeOutput.toString(language))){
                                registerList.add(vnodeOutput.toString(language));
                                registerSize.add(String.valueOf(vnodeOutput.getSize()));
                            }
                        } else if (vnodeOutput.isConstant()){
                            storage = "constant";
                        } else if (vnodeOutput.isAddress()) {
                            storage = "memory";
                            if (!memoryList.contains(vnodeOutput.toString(language))){
                                memoryList.add(vnodeOutput.toString(language));
                                memorySize.add(String.valueOf(vnodeOutput.getSize()));
                            }
                        } else if (vnodeOutput.isUnique()) {
                            storage = "unique";
                        } else {
                            storage = "other";
                        }
                        outIsRegister.setValue(storage);
                        pOutputElement.setAttributeNode(outIsRegister);

                    }
                    Element iNameElement = doc.createElement("name");
                    pcodeElement.appendChild(iNameElement);
                    iNameElement.appendChild(doc.createTextNode(pcode[i].getMnemonic()));
                    Attr inIsRegister;
                    for (int j = 0; j < pcode[i].getNumInputs(); j++) {
                        Element pInputElement = doc.createElement("input_" + j);
                        pcodeElement.appendChild(pInputElement);
                        pInputElement.appendChild(doc.createTextNode(pcode[i].getInput(j).toString(language)));
                        Attr size = doc.createAttribute("size");
                        size.setValue(String.valueOf(pcode[i].getInput(j).getSize()));
                        pInputElement.setAttributeNode(size);
                        inIsRegister = doc.createAttribute("storage");
                        String storage = "";
                        if (pcode[i].getInput(j).isRegister()) {
                            storage = "register";
                            if (!registerList.contains(pcode[i].getInput(j).toString(language))){
                                registerList.add(pcode[i].getInput(j).toString(language));
                                registerSize.add(String.valueOf(pcode[i].getInput(j).getSize()));
                            }
                        } else if (pcode[i].getInput(j).isConstant()){
                            storage = "constant";
                        } else if (pcode[i].getInput(j).isAddress()) {
                            storage = "memory";
                            if (!memoryList.contains(pcode[i].getInput(j).toString(language))){
                                memoryList.add(pcode[i].getInput(j).toString(language));
                                memorySize.add(String.valueOf(pcode[i].getInput(j).getSize()));
                            }
                        } else if (pcode[i].getInput(j).isUnique()) {
                            storage = "unique";
                        } else {
                            storage = "other";
                        }
                        inIsRegister.setValue(storage);
                        pInputElement.setAttributeNode(inIsRegister);
                    }
                }
                y++;
            }
        }
        int x = 0;
        while (x < registerList.size()){
            Element register = doc.createElement("register");
            Attr name = doc.createAttribute("name");
            name.setValue(registerList.get(x));
            register.setAttributeNode(name);
            Attr size = doc.createAttribute("size");
            size.setValue(registerSize.get(x));
            register.setAttributeNode(size);
            globals.appendChild(register);
            x++;
        }
        x = 0;
        while (x < memoryList.size()){
            Element memory_val = doc.createElement("memory");
            Attr name = doc.createAttribute("name");
            name.setValue(memoryList.get(x));
            memory_val.setAttributeNode(name);
            Attr size = doc.createAttribute("size");
            size.setValue(memorySize.get(x));
            memory_val.setAttributeNode(size);
            memory.appendChild(memory_val);
            x++;
        }
        // write the content into xml file
        TransformerFactory transformerFactory = TransformerFactory.newInstance();
        Transformer transformer = transformerFactory.newTransformer();
        DOMSource source = new DOMSource(doc);
        StreamResult result = new StreamResult(new File("/tmp/output.xml"));
        transformer.transform(source, result);
    }
}
