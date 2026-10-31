// Self-authored static-analysis fixture. Never executed by Bytasm or its tests.
// Demonstrates only a statically referenced dynamic library-loading call site.
#include <windows.h>
__attribute__((noinline)) static int fixture_load_library(void) {
  return LoadLibraryA("bytasm-fixture-only.dll") ? 0 : 1;
}
int main(void) { return fixture_load_library(); }
