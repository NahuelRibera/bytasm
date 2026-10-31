// Fixed bounded static extraction. Sample text is data, never configuration.
import ghidra.app.util.headless.HeadlessScript;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.framework.Application;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import com.google.gson.stream.JsonWriter;
import com.google.gson.*;
import java.util.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;

public class BytasmExtract extends HeadlessScript {
    private JsonWriter out;
    private Set<String> selected = new HashSet<>();
    private boolean selected(Function fn, int index) {
        return selected.isEmpty() ? index < 16 && !fn.isExternal() : selected.contains(
            fn.getEntryPoint().getAddressSpace().getName() + ":" + fn.getEntryPoint().toString(false));
    }
    private String bound(String value, int cap) {
        return value.length() > cap ? value.substring(0, cap) : value;
    }
    private void address(Address value) throws IOException {
        String space = value.getAddressSpace().getName();
        String exact = value.toString(false);
        if (space.length() > 64 || exact.length() > 128) {
            throw new IOException("Address identity exceeds protocol bounds");
        }
        out.beginObject();
        out.name("space").value(space);
        out.name("address").value(exact);
        out.endObject();
    }
    private void function(Function fn, DecompInterface decompiler, boolean selected) throws Exception {
        out.beginObject();
        out.name("entry"); address(fn.getEntryPoint());
        out.name("external").value(fn.isExternal());
        out.name("name").value(bound(fn.getName(), 256));
        out.name("name_truncated").value(fn.getName().length() > 256);
        out.name("namespace").value(bound(fn.getParentNamespace().getName(true), 256));
        out.name("namespace_truncated").value(fn.getParentNamespace().getName(true).length() > 256);
        out.name("body_size").value(fn.getBody().getNumAddresses());
        out.name("body_ranges").beginArray();
        AddressRangeIterator ranges = fn.getBody().getAddressRanges(true);
        int rangeCount = 0;
        while (ranges.hasNext() && rangeCount++ < 64) {
            monitor.checkCancelled();
            AddressRange range = ranges.next();
            out.beginObject(); out.name("start"); address(range.getMinAddress());
            out.name("end"); address(range.getMaxAddress());
            out.name("provenance").value("ghidra_function_body"); out.endObject();
        }
        out.endArray(); out.name("body_ranges_truncated").value(ranges.hasNext());
        String code = null;
        if (selected && decompiler != null) {
            DecompileResults result = decompiler.decompileFunction(fn, 5, monitor);
            if (result.decompileCompleted() && result.getDecompiledFunction() != null) {
                code = result.getDecompiledFunction().getC();
            }
        }
        out.name("pseudocode");
        if (code == null) out.nullValue(); else out.value(bound(code, 4096));
        out.name("pseudocode_status").value(!selected ? "not_selected" : code == null ? "failed" : "available");
        out.name("pseudocode_truncated").value(code != null && code.length() > 4096);
        out.name("instructions").beginArray();
        InstructionIterator instructions = currentProgram.getListing().getInstructions(fn.getBody(), true);
        int count = 0;
        while (selected && instructions.hasNext() && count < 64) {
            monitor.checkCancelled();
            Instruction ins = instructions.next();
            out.beginObject(); out.name("address"); address(ins.getAddress());
            StringBuilder bytes = new StringBuilder();
            byte[] raw = ins.getBytes();
            for (int i = 0; i < Math.min(raw.length, 32); i++) bytes.append(String.format("%02x", raw[i] & 255));
            out.name("bytes_hex").value(bytes.toString());
            out.name("text").value(bound(ins.toString(), 256));
            out.name("text_truncated").value(ins.toString().length() > 256);
            out.name("bytes_truncated").value(raw.length > 32);
            out.endObject(); count++;
        }
        out.endArray();
        out.name("instructions_truncated").value(selected && instructions.hasNext());
        out.name("calls").beginArray();
        // Only direct call references originating in the emitted instruction window.
        instructions = currentProgram.getListing().getInstructions(fn.getBody(), true);
        int scanned = 0, calls = 0;
        boolean capped = false;
        while (selected && instructions.hasNext() && scanned++ < 64) {
            Instruction ins = instructions.next();
            for (Reference reference : ins.getReferencesFrom()) {
                if (!reference.getReferenceType().isCall() || reference.getReferenceType().isComputed()) continue;
                if (calls >= 64) { capped = true; break; }
                out.beginObject(); out.name("source"); address(reference.getFromAddress());
                out.name("target"); address(reference.getToAddress()); out.endObject(); calls++;
            }
        }
        out.endArray();
        out.name("calls_truncated").value(selected && (capped || instructions.hasNext()));
        // Exact outgoing listing references only. No name or proximity joins.
        out.name("references").beginArray();
        instructions = currentProgram.getListing().getInstructions(fn.getBody(), true);
        int refScanned = 0, refCount = 0;
        boolean refsCapped = false;
        while (selected && instructions.hasNext() && refScanned++ < 64) {
            monitor.checkCancelled();
            Instruction ins = instructions.next();
            for (Reference reference : ins.getReferencesFrom()) {
                if (refCount >= 64) { refsCapped = true; break; }
                Address target = reference.getToAddress();
                Data data = currentProgram.getListing().getDefinedDataAt(target);
                Symbol symbol = currentProgram.getSymbolTable().getPrimarySymbol(target);
                Function targetFunction = currentProgram.getFunctionManager().getFunctionAt(target);
                Function resolved = targetFunction != null && targetFunction.isThunk()
                    ? targetFunction.getThunkedFunction(true) : null;
                Address resolvedExternal = resolved != null && resolved.isExternal()
                    ? resolved.getEntryPoint() : null;
                String kind = reference.isExternalReference() || target.isExternalAddress() || resolvedExternal != null
                    ? "external_symbol" : data != null && data.hasStringValue()
                    ? "string" : data != null ? "data" : null;
                if (kind == null) continue;
                String name = resolvedExternal != null ? resolved.getName(true) : symbol == null ? null : symbol.getName(true);
                String preview = data == null ? null : data.getDefaultValueRepresentation();
                out.beginObject(); out.name("source"); address(reference.getFromAddress());
                out.name("target"); address(target);
                out.name("kind").value(kind);
                out.name("resolved_external_target");
                if (resolvedExternal == null) out.nullValue(); else address(resolvedExternal);
                out.name("resolved_external_provenance");
                if (resolvedExternal == null) out.nullValue(); else out.value("ghidra_function_thunk");
                out.name("reference_type").value(bound(reference.getReferenceType().toString(), 256));
                out.name("provenance").value("ghidra_instruction_reference");
                out.name("target_name"); if (name == null) out.nullValue(); else out.value(bound(name, 256));
                out.name("target_name_truncated").value(name != null && name.length() > 256);
                out.name("preview"); if (preview == null) out.nullValue(); else out.value(bound(preview, 512));
                out.name("preview_truncated").value(preview != null && preview.length() > 512);
                out.endObject(); refCount++;
            }
        }
        out.endArray();
        out.name("references_truncated").value(selected && (refsCapped || instructions.hasNext()));
        out.endObject();
    }
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 5 || currentProgram == null) throw new IllegalArgumentException("Invalid extraction context");
        if (!Application.getApplicationVersion().equals("12.2")) throw new IllegalStateException("Unsupported Ghidra");
        if (!currentProgram.getExecutableSHA256().equals(args[1])) throw new IllegalStateException("Input identity mismatch");
        JsonArray entries = JsonParser.parseString(Files.readString(Path.of(args[4]))).getAsJsonArray();
        if (entries.size() > 8) throw new IllegalArgumentException("Selection exceeds bounds");
        for (JsonElement element : entries) {
            JsonObject entry = element.getAsJsonObject();
            selected.add(entry.get("space").getAsString() + ":" + entry.get("address").getAsString());
        }
        DecompInterface decompiler = new DecompInterface();
        DecompileOptions options = new DecompileOptions();
        options.setMaxPayloadMBytes(1);
        decompiler.setOptions(options);
        boolean opened = decompiler.openProgram(currentProgram);
        try (Writer file = Files.newBufferedWriter(Path.of(args[0]), StandardCharsets.UTF_8)) {
            out = new JsonWriter(file); out.setSerializeNulls(true);
            out.beginObject();
            out.name("schema_version").value("ghidra-3");
            out.name("input_sha256").value(args[1]);
            out.name("ghidra_version").value(Application.getApplicationVersion());
            out.name("provider_host").value(bound(System.getProperty("os.name") + " " + System.getProperty("os.arch"), 256));
            out.name("profile_sha256").value(args[2]); out.name("script_sha256").value(args[3]);
            out.name("language_id").value(bound(currentProgram.getLanguageID().getIdAsString(), 256));
            out.name("compiler").value(bound(currentProgram.getCompilerSpec().getCompilerSpecID().getIdAsString(), 256));
            FunctionManager manager = currentProgram.getFunctionManager();
            int total = manager.getFunctionCount();
            FunctionIterator functions = manager.getFunctions(true);
            out.name("functions").beginArray(); int count = 0;
            while (functions.hasNext() && count < 1024) {
                monitor.checkCancelled(); Function fn = functions.next();
                function(fn, opened ? decompiler : null, selected(fn, count)); count++;
            }
            // getFunctionCount includes external functions. Include their exact
            // identities after internal functions so the denominator matches.
            functions = manager.getExternalFunctions();
            while (functions.hasNext() && count < 1024) {
                monitor.checkCancelled(); Function fn = functions.next();
                function(fn, null, selected(fn, count)); count++;
            }
            out.endArray(); out.name("function_count").value(total);
            out.name("functions_truncated").value(total > count);
            out.name("analysis_timed_out").value(analysisTimeoutOccurred());
            out.name("limitations").beginArray();
            out.value("Static analysis does not establish runtime behavior or intent.");
            out.value("Pseudocode is Ghidra reconstruction, not original source code.");
            out.value("Details cover the first 16 internal functions or up to 8 explicitly selected entries; calls cover at most 64 instructions each.");
            out.value("Names and namespaces are limited to 256 characters; instruction bytes to 32 bytes.");
            out.value("References cover at most 64 listing instructions and 64 exact targets per selected function; body ranges retain at most 64 inclusive ranges. Unresolved targets and interior data references are not inferred.");
            out.endArray(); out.endObject(); out.flush();
        } finally { decompiler.dispose(); }
    }
}
