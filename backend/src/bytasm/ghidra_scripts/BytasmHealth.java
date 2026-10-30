// Harmless Headless self-test: no imported program, sample or external service.
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.framework.Application;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.util.DefaultLanguageService;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.charset.StandardCharsets;

public class BytasmHealth extends GhidraScript {
    @Override
    public void run() throws Exception {
        if (currentProgram != null || !Application.getApplicationVersion().equals("12.2")) {
            throw new IllegalStateException("Unexpected self-test context");
        }
        // An empty in-memory database checks language initialization and the
        // native decompiler transport without importing or executing any bytes.
        Language language = DefaultLanguageService.getLanguageService().getLanguage(
            new LanguageID("x86:LE:64:default"));
        ProgramDB empty = new ProgramDB("Bytasm self-test", language,
            language.getDefaultCompilerSpec(), this);
        DecompInterface decompiler = new DecompInterface();
        try {
            if (!decompiler.openProgram(empty)) {
                throw new IllegalStateException("Decompiler self-test failed");
            }
            Files.writeString(Path.of(getScriptArgs()[0]),
                "{\"healthy\":true,\"version\":\"12.2\"}", StandardCharsets.UTF_8);
        } finally {
            decompiler.dispose();
            empty.release(this);
        }
    }
}
