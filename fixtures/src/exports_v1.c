// fixtures/src/exports_v1.c
// Bytasm test fixture, written for Bytasm. Never executed or loaded by Bytasm or its tests.
//
// Purpose: a PE DLL with a known export table (two named functions) and a
// known import, so the adapter's PE export and import paths are tested on
// real linker output rather than only on a generated image.
int puts(const char *s);

__declspec(dllexport) int bytasm_fixture_add(int a, int b) { return a + b; }

__declspec(dllexport) const char *bytasm_fixture_version(void) {
  puts("bytasm fixture: exports v1");
  return "exports_v1";
}
