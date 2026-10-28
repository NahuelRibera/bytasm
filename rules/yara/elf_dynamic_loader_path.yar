// Bytasm rule set, written for Bytasm. Descriptive only: a match means the
// pattern was found, not that anything about the file is proven.
//
// Dynamically linked Linux programs name their loader (the ELF program
// interpreter). This rule only finds the text; it does not parse PT_INTERP.
rule elf_dynamic_loader_path {
  meta:
    description = "An ELF file contains a Linux dynamic loader path such as /lib64/ld-linux-x86-64.so.2"
    author = "Bytasm"
    observation = "text pattern in an ELF file"
  strings:
    $ld = /\/lib(64)?\/ld-linux[-a-z0-9_.]{0,32}\.so\.[0-9]/ ascii
  condition:
    uint32(0) == 0x464C457F and $ld
}
