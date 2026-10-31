// Self-authored static-analysis fixture. Never executed by Bytasm or its tests.
// Benign negative control: an unrelated Windows API call and no capability under test.
#include <windows.h>
__attribute__((noinline)) static int fixture_unrelated(void) { return GetTickCount() == 0; }
int main(void) { return fixture_unrelated(); }
