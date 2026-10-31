// Self-authored static-analysis fixture. Never executed by Bytasm or its tests.
// Demonstrates only a statically referenced INI configuration-read call site.
#include <windows.h>
__attribute__((noinline)) static int fixture_read_configuration(void) {
  char value[32];
  return GetPrivateProfileStringA("bytasm", "fixture", "", value, sizeof(value),
                                  ".\\bytasm-fixture-only.ini") ? 0 : 1;
}
int main(void) { return fixture_read_configuration(); }
