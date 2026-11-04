// DecompileExport.java — Ghidra headless post-script for binscope.
//
// Emits, to the output file given as the first script arg:
//   1. A machine-readable "#MAP key: values" header (entry points, imports,
//      strings sample, most-called functions, and which functions call
//      network / crypto / file / process / registry / dynamic-load APIs).
//   2. The decompiled C of every function (optionally filtered), each preceded
//      by "// FUNCTION <name> @ <address>".
//   3. A trailer "/* exported N functions */" so the caller can confirm the
//      script finished (analyzeHeadless exits 0 even when a script throws).
//
// Optional script args after the output path:
//   arg[1] = case-insensitive substring filter on function name
//   arg[2] = max number of functions to decompile
//
// @category binscope

import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.address.Address;
import ghidra.program.util.DefinedDataIterator;
import ghidra.program.model.data.StringDataInstance;

import java.io.PrintWriter;
import java.io.FileWriter;
import java.util.*;

public class DecompileExport extends GhidraScript {

    // API-name substrings grouped by concern. Membership is by the called
    // function's name containing any of these (case-insensitive).
    static final Map<String, String[]> CONCERNS = new LinkedHashMap<>();
    static {
        CONCERNS.put("network", new String[]{"socket","connect","send","recv",
            "InternetOpen","WSAStartup","URLDownload","WinHttp","getaddrinfo",
            "HttpSendRequest","curl"});
        CONCERNS.put("crypto", new String[]{"Crypt","BCrypt","EVP_","AES","RC4",
            "MD5","SHA","Rijndael"});
        CONCERNS.put("file", new String[]{"CreateFile","ReadFile","WriteFile",
            "fopen","fwrite","unlink","DeleteFile","MoveFile"});
        CONCERNS.put("process", new String[]{"CreateProcess","WriteProcessMemory",
            "CreateRemoteThread","VirtualAllocEx","OpenProcess","ShellExecute",
            "WinExec","execve","fork","NtMapViewOfSection"});
        CONCERNS.put("registry", new String[]{"RegOpenKey","RegSetValue",
            "RegCreateKey","RegQueryValue","RegDeleteKey"});
        CONCERNS.put("dynload", new String[]{"LoadLibrary","GetProcAddress",
            "dlopen","dlsym"});
    }

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1) {
            println("DecompileExport: missing output path arg");
            return;
        }
        String outPath = args[0];
        String nameFilter = args.length >= 2 ? args[1].toLowerCase() : "";
        int maxFuncs = args.length >= 3 ? Integer.parseInt(args[2]) : 0;

        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(currentProgram);

        FunctionManager fm = currentProgram.getFunctionManager();
        ReferenceManager refMgr = currentProgram.getReferenceManager();
        SymbolTable symTab = currentProgram.getSymbolTable();

        // Build concern buckets + a called-function frequency table.
        Map<String, TreeSet<String>> buckets = new LinkedHashMap<>();
        for (String c : CONCERNS.keySet()) buckets.put(c, new TreeSet<String>());
        Map<String, Integer> callCount = new HashMap<>();

        List<Function> allFuncs = new ArrayList<>();
        for (Function f : fm.getFunctions(true)) allFuncs.add(f);

        for (Function f : allFuncs) {
            Set<Function> callees = f.getCalledFunctions(monitor);
            for (Function callee : callees) {
                String cn = callee.getName();
                callCount.merge(cn, 1, Integer::sum);
                String lower = cn.toLowerCase();
                for (Map.Entry<String, String[]> e : CONCERNS.entrySet()) {
                    for (String needle : e.getValue()) {
                        if (lower.contains(needle.toLowerCase())) {
                            buckets.get(e.getKey()).add(f.getName());
                            break;
                        }
                    }
                }
            }
        }

        PrintWriter out = new PrintWriter(new FileWriter(outPath));

        // --- header map ---
        // entry points
        StringBuilder entries = new StringBuilder();
        for (Address a : currentProgram.getSymbolTable().getExternalEntryPointIterator()) {
            Function f = fm.getFunctionAt(a);
            entries.append(f != null ? f.getName() : a.toString()).append(",");
        }
        out.println("#MAP entry: " + entries);

        // most-called functions
        List<Map.Entry<String,Integer>> calls = new ArrayList<>(callCount.entrySet());
        calls.sort((x,y) -> y.getValue() - x.getValue());
        StringBuilder mc = new StringBuilder();
        for (int i = 0; i < Math.min(20, calls.size()); i++) {
            mc.append(calls.get(i).getKey()).append("(").append(calls.get(i).getValue()).append("),");
        }
        out.println("#MAP mostcalled: " + mc);

        // concern buckets
        for (Map.Entry<String, TreeSet<String>> e : buckets.entrySet()) {
            if (e.getValue().isEmpty()) continue;
            StringBuilder sb = new StringBuilder();
            int i = 0;
            for (String name : e.getValue()) {
                sb.append(name).append(",");
                if (++i >= 40) break;
            }
            out.println("#MAP " + e.getKey() + ": " + sb);
        }

        // a sample of defined strings
        int strCount = 0;
        StringBuilder strs = new StringBuilder();
        for (ghidra.program.model.listing.Data d :
                DefinedDataIterator.definedStrings(currentProgram)) {
            String v = StringDataInstance.getStringDataInstance(d).getStringValue();
            if (v != null && v.length() >= 5) {
                strs.append(v.replaceAll("[\\r\\n,]", " ")).append(" | ");
                if (++strCount >= 30) break;
            }
        }
        out.println("#MAP strings: " + strs);
        out.println("");

        // --- decompiled functions ---
        int exported = 0;
        for (Function f : allFuncs) {
            if (f.isThunk()) continue;
            if (!nameFilter.isEmpty() && !f.getName().toLowerCase().contains(nameFilter))
                continue;
            if (maxFuncs > 0 && exported >= maxFuncs) break;
            DecompileResults dr = decomp.decompileFunction(f, 60, monitor);
            out.println("// FUNCTION " + f.getName() + " @ " + f.getEntryPoint());
            if (dr != null && dr.decompileCompleted()) {
                out.println(dr.getDecompiledFunction().getC());
            } else {
                out.println("// <decompilation failed>");
            }
            out.println("");
            exported++;
        }

        out.println("/* exported " + exported + " functions */");
        out.close();
        println("DecompileExport: wrote " + exported + " functions to " + outPath);
    }
}
