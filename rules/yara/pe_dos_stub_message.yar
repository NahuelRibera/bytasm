// Bytasm rule set, written for Bytasm. Descriptive only: a match means the
// pattern was found, not that anything about the file is proven.
rule pe_dos_stub_message {
  meta:
    description = "A PE file whose DOS stub contains the usual 'cannot be run in DOS mode' text"
    author = "Bytasm"
    observation = "text pattern in a PE file"
  strings:
    $stub = "This program cannot be run in DOS mode" ascii
  condition:
    uint16(0) == 0x5A4D and $stub
}
