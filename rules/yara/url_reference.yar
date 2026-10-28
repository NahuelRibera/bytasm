// Bytasm rule set, written for Bytasm. Descriptive only: a match means the
// pattern was found, not that anything about the file is proven.
rule url_reference {
  meta:
    description = "Contains text that looks like the start of an http:// or https:// URL"
    author = "Bytasm"
    observation = "text pattern"
  strings:
    $http = "http://" ascii wide nocase
    $https = "https://" ascii wide nocase
  condition:
    any of them
}
