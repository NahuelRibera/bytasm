// Bytasm rule set, written for Bytasm. Descriptive only: a match means the
// pattern was found, not that anything about the file is proven.
//
// A section *named* like UPX's is not proof that the file is packed: any
// linker can give a section this name.
import "pe"

rule upx_style_section_name {
  meta:
    description = "A PE section is named UPX0 or UPX1 (UPX-style section name; not proof of packing)"
    author = "Bytasm"
    observation = "section name"
  strings:
    $upx0 = "UPX0" ascii
    $upx1 = "UPX1" ascii
  condition:
    pe.is_pe and any of them and
    for any section in pe.sections : (section.name == "UPX0" or section.name == "UPX1")
}
