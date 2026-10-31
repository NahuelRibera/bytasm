// Self-authored static-analysis fixture. Never executed by Bytasm or its tests.
// Demonstrates only a statically referenced file-read API call site.
#include <windows.h>
__attribute__((noinline)) static int fixture_read_file(void) {
  char buffer[16];
  DWORD count = 0;
  return ReadFile(GetStdHandle(STD_INPUT_HANDLE), buffer, sizeof(buffer), &count, NULL) ? 0 : 1;
}
int main(void) { return fixture_read_file(); }
