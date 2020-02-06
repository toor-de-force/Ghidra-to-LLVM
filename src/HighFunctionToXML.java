import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.util.headless.HeadlessScript;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.lang.Language;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.*;
import org.w3c.dom.Attr;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.File;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;


public class HighFunctionToXML extends HeadlessScript {

    @Override
    protected void run() throws Exception {

        DocumentBuilderFactory dFactory = DocumentBuilderFactory.newInstance();
        DocumentBuilder dBuilder = dFactory.newDocumentBuilder();
        Document doc = dBuilder.newDocument();
        Element rootElement = doc.createElement("program");
        doc.appendChild(rootElement);

        DecompileOptions options = new DecompileOptions();
        DecompInterface ifc = new DecompInterface();
        ifc.openProgram(currentProgram);
        ifc.setOptions(options);
        ifc.setSimplificationStyle("decompile");
        Language language = currentProgram.getLanguage();
        AddressSetView set = currentProgram.getMemory().getExecuteSet();
        Listing listing = currentProgram.getListing();
        FunctionIterator fi = listing.getFunctions(true);

        Element globals = doc.createElement("globals");
        rootElement.appendChild(globals);
        List globalList = new ArrayList();
        List globalSizes = new ArrayList();

        while (fi.hasNext()) {

            Function func = fi.next();
            int timeout_secs = 60;
            DecompileResults results = ifc.decompileFunction(func, timeout_secs, monitor);
            HighFunction hf = results.getHighFunction();
            ArrayList<PcodeBlockBasic> blockList = hf.getBasicBlocks();
            Element functionElement = doc.createElement("function");
            rootElement.appendChild(functionElement);
            Attr fNameAttr = doc.createAttribute("name");
            fNameAttr.setValue(func.getName());
            functionElement.setAttributeNode(fNameAttr);
            FunctionPrototype funcpro = hf.getFunctionPrototype();
            if(!funcpro.hasNoReturn()){
                Attr fOutputAttr = doc.createAttribute("outputType");
                fOutputAttr.setValue(funcpro.getReturnType().getName());
                functionElement.setAttributeNode(fOutputAttr);
                Attr fOutputSizeAttr = doc.createAttribute("outputTypeLength");
                fOutputSizeAttr.setValue("" + funcpro.getReturnType().getLength());
                functionElement.setAttributeNode(fOutputSizeAttr);
            }
            Attr fInputAttr;
            Attr fInputSizeAttr;
            Attr fInputStorageAttr;
            Attr inIsRegister;
            for(int r = 0; r < funcpro.getNumParams(); r++){
                fInputAttr = doc.createAttribute("inputType_" + r);
                fInputAttr.setValue(funcpro.getParam(r).getDataType().getName());
                functionElement.setAttributeNode(fInputAttr);
                fInputSizeAttr = doc.createAttribute("inputTypeLength_" + r);
                fInputSizeAttr.setValue("" + funcpro.getParam(r).getSize());
                functionElement.setAttributeNode(fInputSizeAttr);
                fInputStorageAttr = doc.createAttribute("inputStorage_" + r);
                fInputStorageAttr.setValue("" + funcpro.getParam(r).getStorage());
                functionElement.setAttributeNode(fInputStorageAttr);
                inIsRegister = doc.createAttribute("inStorageType_" + r);
                String storage = "";
                VariableStorage varStorage = funcpro.getParam(r).getStorage();
                if (varStorage.isRegisterStorage()) {
                    storage = "register";
                } else if (varStorage.isConstantStorage()){
                    storage = "constant";
                } else if (varStorage.isMemoryStorage()) {
                    storage = "memory";
                } else {
                    storage = "other";
                }
                functionElement.setAttributeNode(inIsRegister);
            }


            for(int i = 0; i < blockList.size(); i++){
                int j = 0;
                PcodeBlockBasic block = blockList.get(i);
                Iterator<PcodeOp> pi = block.getIterator();
                Element blockElement = doc.createElement("BB_" + i);
                Attr bStartAttr = doc.createAttribute("start");
                bStartAttr.setValue(block.getStart().toString());
                blockElement.setAttributeNode((bStartAttr));
                Attr bEndAttr = doc.createAttribute("end");
                bEndAttr.setValue(block.getStop().toString());
                blockElement.setAttributeNode((bEndAttr));
                functionElement.appendChild(blockElement);

                for(int p = 0; p < block.getInSize(); p++){
                    PcodeBlock inBlock = block.getIn(p);
                    Attr inAttr = doc.createAttribute("in_" + p);
                    inAttr.setValue(inBlock.toString().split("@")[1]);
                    blockElement.setAttributeNode((inAttr));
                }
                for(int q = 0; q < block.getOutSize(); q++) {
                    PcodeBlock outBlock = block.getOut(q);
                    Attr outAttr = doc.createAttribute("out_" + q);
                    outAttr.setValue(outBlock.toString().split("@")[1]);
                    blockElement.setAttributeNode((outAttr));
                }

                while (pi.hasNext()){
                    PcodeOp pcode = pi.next();
                    Element pcodeElement = doc.createElement("pcode_" + j);
                    blockElement.appendChild(pcodeElement);
                    Element pNameElement = doc.createElement("name");
                    pcodeElement.appendChild(pNameElement);
                    pNameElement.appendChild(doc.createTextNode(pcode.getMnemonic()));
                    j++;
                    Varnode vnodeOutput = pcode.getOutput();
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
                            String val = vnodeOutput.toString(language);
                            if (!globalList.contains(val)) {
                                globalList.add(val);
                                globalSizes.add("" + vnodeOutput.getSize());
                            }
                        } else if (vnodeOutput.isConstant()){
                            storage = "constant";
                        } else if (vnodeOutput.isAddress()) {
                            storage = "memory";
                        } else if (vnodeOutput.isUnique()) {
                            storage = "unique";
                        } else {
                            storage = "other";
                        }
                        outIsRegister.setValue(storage);
                        pOutputElement.setAttributeNode(outIsRegister);
                    }
                    for (int k = 0; k < pcode.getNumInputs(); k++) {
                        Element pInputElement = doc.createElement("input_" + k);
                        pcodeElement.appendChild(pInputElement);
                        pInputElement.appendChild(doc.createTextNode(pcode.getInput(k).toString(language)));
                        Attr size = doc.createAttribute("size");
                        size.setValue(String.valueOf(pcode.getInput(k).getSize()));
                        pInputElement.setAttributeNode(size);
                        inIsRegister = doc.createAttribute("storage");
                        String storage = "";
                        if (pcode.getInput(k).isRegister()) {
                            storage = "register";
                            String val = pcode.getInput(k).toString(language);
                            if (!globalList.contains(val)) {
                                globalList.add(val);
                                globalSizes.add("" + pcode.getInput(k).getSize());
                            }
                        } else if (pcode.getInput(k).isConstant()){
                            storage = "constant";
                        } else if (pcode.getInput(k).isAddress()) {
                            storage = "memory";
                        } else if (pcode.getInput(k).isUnique()) {
                            storage = "unique";
                        } else {
                            storage = "other";
                        }
                        inIsRegister.setValue(storage);
                        pInputElement.setAttributeNode(inIsRegister);
                    }
                }

            }
        }

        int x = 0;
        while (x < globalList.size()){
            Element global = doc.createElement("register");
            globals.appendChild(global);
            Attr gName = doc.createAttribute("name");
            gName.setValue(String.valueOf(globalList.get(x).toString()));
            global.setAttributeNode(gName);
            Attr gSize = doc.createAttribute("size");
            gSize.setValue(String.valueOf(globalSizes.get(x)));
            global.setAttributeNode(gSize);

            x++;
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
