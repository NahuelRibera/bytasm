// Bytasm rule set, written for Bytasm. Descriptive only: a match means the
// pattern was found, not that anything about the file is proven.
//
// Almost every Windows program imports from KERNEL32.dll. The rule finds the
// library name as text; it does not read the import table.
rule pe_kernel32_import_name {
  meta:
    description = "A PE file contains the text KERNEL32.dll (usually the name of an imported Windows library)"
    author = "Bytasm"
    observation = "text pattern in a PE file"
  strings:
    $k32 = "kernel32.dll" ascii nocase
  condition:
    uint16(0) == 0x5A4D and $k32
}
