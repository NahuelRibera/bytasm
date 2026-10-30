// Self-authored static-analysis fixture. Never executed by Bytasm or its tests.
// Demonstrates only a statically referenced environment-query API.
#include <windows.h>
int main(void) {
  char value[64];
  return GetEnvironmentVariableA("BYTASM_FIXTURE_ONLY", value, sizeof(value)) ? 0 : 1;
}
