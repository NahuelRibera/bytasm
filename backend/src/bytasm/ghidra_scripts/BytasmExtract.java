// Fixed bounded static extraction. Sample text is data, never configuration.
import ghidra.app.util.headless.HeadlessScript;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.framework.Application;
import ghidra.program.model.address.*;
import ghidra.program.model.block.*;
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
        // ghidra-5: Ghidra's own thunk resolution, and initialized data that
        // references this entry (for example IAT or GOT slots). Never inferred.
        Function thunked = fn.isThunk() ? fn.getThunkedFunction(true) : null;
        out.name("thunk_target");
        if (thunked == null) out.nullValue(); else address(thunked.getEntryPoint());
        out.name("pointer_slots").beginArray();
        int slots = 0, slotScan = 0;
        boolean slotsCapped = false;
        ReferenceIterator incoming = currentProgram.getReferenceManager().getReferencesTo(fn.getEntryPoint());
        while (incoming.hasNext() && slotScan++ < 4096) {
            monitor.checkCancelled();
            Reference reference = incoming.next();
            Address from = reference.getFromAddress();
            if (reference.getReferenceType().isFlow() || !from.isMemoryAddress()) continue;
            if (currentProgram.getListing().getInstructionAt(from) != null) continue;
            ghidra.program.model.mem.MemoryBlock block = currentProgram.getMemory().getBlock(from);
            if (block == null || !block.isInitialized()) continue;
            if (slots >= 4) { slotsCapped = true; break; }
            out.beginObject(); out.name("address"); address(from);
            out.name("reference_type").value(bound(reference.getReferenceType().toString(), 256));
            out.name("provenance").value("ghidra_reference_to_entry"); out.endObject(); slots++;
        }
        out.endArray();
        out.name("pointer_slots_truncated").value(slotsCapped || incoming.hasNext() && slotScan > 4096);
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
        // Targets that are not the start of defined data or an external symbol
        // (undefined memory, code, interior of a data item) are omitted, not emitted.
        out.name("references").beginArray();
        instructions = currentProgram.getListing().getInstructions(fn.getBody(), true);
        int refScanned = 0, refCount = 0;
        boolean refsCapped = false;
        while (selected && !refsCapped && instructions.hasNext() && refScanned++ < 64) {
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
        structure(fn, selected);
        out.endObject();
    }
    // ghidra-5: static structure of a selected function from Ghidra's
    // BasicBlockModel and instruction flow types. Unresolved destinations stay
    // unresolved; nothing here describes execution.
    private void structure(Function fn, boolean selected) throws Exception {
        Listing listing = currentProgram.getListing();
        out.name("basic_blocks").beginArray();
        int blockCount = 0, retained = 0;
        boolean countCapped = false;
        if (selected) {
            BasicBlockModel model = new BasicBlockModel(currentProgram);
            CodeBlockIterator blocks = model.getCodeBlocksContaining(fn.getBody(), monitor);
            while (blocks.hasNext()) {
                monitor.checkCancelled();
                if (blockCount >= 4096) { countCapped = true; break; }
                CodeBlock block = blocks.next(); blockCount++;
                if (retained >= 128) continue;
                retained++;
                out.beginObject();
                out.name("start"); address(block.getMinAddress());
                out.name("end"); address(block.getMaxAddress());
                int count = 0; Instruction last = null;
                InstructionIterator inside = listing.getInstructions(block, true);
                while (inside.hasNext() && count < 4096) { last = inside.next(); count++; }
                out.name("instruction_count").value(count);
                out.name("terminal").value(last != null && last.getFlowType().isTerminal());
                out.name("flows").beginArray();
                int flows = 0; boolean flowsCapped = false;
                CodeBlockReferenceIterator destinations = block.getDestinations(monitor);
                while (destinations.hasNext()) {
                    CodeBlockReference ref = destinations.next();
                    FlowType flow = ref.getFlowType();
                    if (flow.isCall()) continue;
                    String kind = flow.isFallthrough() ? "fallthrough" : flow.isComputed() ? "computed_jump"
                        : flow.isConditional() ? "conditional_jump" : flow.isJump() ? "unconditional_jump" : null;
                    if (kind == null) continue;
                    if (flows >= 8) { flowsCapped = true; break; }
                    Address target = ref.getDestinationAddress();
                    out.beginObject(); out.name("target");
                    if (target == null) out.nullValue(); else address(target);
                    out.name("kind").value(kind);
                    out.name("internal").value(target != null && fn.getBody().contains(target));
                    out.name("provenance").value("ghidra_basic_block_model"); out.endObject(); flows++;
                }
                out.endArray();
                out.name("flows_truncated").value(flowsCapped);
                out.endObject();
            }
        }
        out.endArray();
        out.name("basic_blocks_truncated").value(selected && blockCount > retained);
        out.name("basic_block_count"); if (selected) out.value(blockCount); else out.nullValue();
        out.name("basic_block_count_capped").value(countCapped);
        int total = 0; boolean totalCapped = false;
        if (selected) {
            InstructionIterator all = listing.getInstructions(fn.getBody(), true);
            while (all.hasNext()) {
                if (total >= 65536) { totalCapped = true; break; }
                all.next(); total++;
            }
        }
        out.name("instruction_count"); if (selected) out.value(total); else out.nullValue();
        out.name("instruction_count_capped").value(totalCapped);
        out.name("call_sites").beginArray();
        int sites = 0, scanned = 0;
        boolean sitesCapped = false;
        if (selected) {
            InstructionIterator calls = listing.getInstructions(fn.getBody(), true);
            while (calls.hasNext()) {
                monitor.checkCancelled();
                if (scanned >= 4096) { sitesCapped = true; break; }
                Instruction ins = calls.next(); scanned++;
                FlowType flow = ins.getFlowType();
                if (!flow.isCall()) continue;
                if (sites >= 128) { sitesCapped = true; break; }
                Address target = null;
                for (Reference reference : ins.getReferencesFrom()) {
                    if (reference.getReferenceType().isCall()) { target = reference.getToAddress(); break; }
                }
                out.beginObject(); out.name("source"); address(ins.getAddress());
                out.name("kind").value(flow.isComputed() ? "indirect" : "direct");
                out.name("target"); if (target == null) out.nullValue(); else address(target);
                out.name("target_basis"); if (target == null) out.nullValue(); else out.value("ghidra_call_reference");
                out.name("provenance").value("ghidra_instruction_flow"); out.endObject(); sites++;
            }
        }
        out.endArray();
        out.name("call_sites_truncated").value(sitesCapped);
    }
    // Ghidra's own address-to-file-bytes mapping. Python never derives a file
    // offset for a Ghidra address without one of these tool-reported ranges.
    private void memoryMap() throws Exception {
        out.name("image_base"); address(currentProgram.getImageBase());
        out.name("memory_blocks").beginArray();
        int blocks = 0;
        boolean blocksCapped = false;
        for (ghidra.program.model.mem.MemoryBlock block : currentProgram.getMemory().getBlocks()) {
            monitor.checkCancelled();
            if (blocks >= 64) { blocksCapped = true; break; }
            out.beginObject();
            out.name("name").value(bound(block.getName(), 256));
            out.name("name_truncated").value(block.getName().length() > 256);
            out.name("start"); address(block.getStart());
            out.name("end"); address(block.getEnd());
            out.name("read").value(block.isRead());
            out.name("write").value(block.isWrite());
            out.name("execute").value(block.isExecute());
            out.name("initialized").value(block.isInitialized());
            out.name("file_ranges").beginArray();
            int ranges = 0;
            boolean rangesCapped = false;
            for (ghidra.program.model.mem.MemoryBlockSourceInfo info : block.getSourceInfos()) {
                Optional<ghidra.program.database.mem.FileBytes> bytes = info.getFileBytes();
                if (bytes.isEmpty() || info.getFileBytesOffset() < 0) continue;
                if (ranges >= 16) { rangesCapped = true; break; }
                out.beginObject();
                out.name("start"); address(info.getMinAddress());
                out.name("end"); address(info.getMaxAddress());
                out.name("file_offset").value(bytes.get().getFileOffset() + info.getFileBytesOffset());
                out.name("provenance").value("ghidra_memory_block_file_bytes");
                out.endObject(); ranges++;
            }
            out.endArray();
            out.name("file_ranges_truncated").value(rangesCapped);
            out.endObject(); blocks++;
        }
        out.endArray();
        out.name("memory_blocks_truncated").value(blocksCapped);
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
            out.name("schema_version").value("ghidra-5");
            out.name("input_sha256").value(args[1]);
            out.name("ghidra_version").value(Application.getApplicationVersion());
            out.name("provider_host").value(bound(System.getProperty("os.name") + " " + System.getProperty("os.arch"), 256));
            out.name("profile_sha256").value(args[2]); out.name("script_sha256").value(args[3]);
            out.name("language_id").value(bound(currentProgram.getLanguageID().getIdAsString(), 256));
            out.name("compiler").value(bound(currentProgram.getCompilerSpec().getCompilerSpecID().getIdAsString(), 256));
            memoryMap();
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
            out.value("References cover at most 64 listing instructions and 64 exact targets per selected function; body ranges retain at most 64 inclusive ranges. References to undefined memory, code or the interior of a data item are omitted, not reported as unresolved.");
            out.value("Memory blocks retain at most 64 blocks and 16 file-backed ranges per block; uninitialized or synthetic blocks have no file range.");
            out.value("Selected functions retain at most 128 basic blocks (8 flows each) and 128 call sites; counts stop at 4096 blocks and 65536 instructions. Unresolved indirect calls and computed jumps are reported without a target.");
            out.value("Pointer slots are at most 4 initialized data references to each function entry; thunk targets are Ghidra's own thunk resolution.");
            out.endArray(); out.endObject(); out.flush();
        } finally { decompiler.dispose(); }
    }
}
