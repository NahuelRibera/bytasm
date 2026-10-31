# Curated static capability rules

The two environment rules are unchanged upstream capa-rules v10.0.0 files under
Apache-2.0 (see ruleset.json for exact sources and hashes). Five additional rules
were authored by Bytasm contributors, Apache-2.0, authored subset version 1.0.0.
The upstream version identifies the upstream base and compatible capa engine;
it does not imply the authored rules came from upstream. The manifest snapshot
hash binds the full mixed subset.

The authored rules match function-level API features emitted by capa, not an
import inventory or a string occurrence. They cover process creation, HTTP
requests, file reads, INI reads, and dynamic library loading. These are ordinary
application capabilities and never establish malicious intent or execution.
Feature-level positive and benign negative tests verify rule semantics. Each
authored rule also matches one self-authored, never-executed compiled PE fixture
through the real capa 10.0.0 `full-static` path (`fixtures/BUILD_INFO.txt`);
two benign controls (unrelated calls; API names as text and stored but uncalled
imports) produce no match. Rule filenames differ from rule names: results are
verified against the exact packaged rule text, never a derived filename.
