// Self-authored static-analysis fixture. Never executed by Bytasm or its tests.
// Demonstrates only a statically referenced process-creation API call site.
#include <windows.h>
__attribute__((noinline)) static int fixture_create_process(void) {
  STARTUPINFOA startup = {sizeof(startup)};
  PROCESS_INFORMATION process;
  char command[] = "bytasm-fixture-only.invalid";
  return CreateProcessA(NULL, command, NULL, NULL, FALSE, 0, NULL, NULL, &startup, &process) ? 0 : 1;
}
int main(void) { return fixture_create_process(); }
