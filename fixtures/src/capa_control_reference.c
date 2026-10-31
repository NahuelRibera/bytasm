// Self-authored static-analysis fixture. Never executed by Bytasm or its tests.
// Benign negative control: the APIs under test appear only as text and as
// imported addresses that are stored, never called. Static call features absent.
#include <windows.h>
static const char *const names[] = {"CreateProcessA", "WinHttpSendRequest", "ReadFile",
                                    "GetPrivateProfileStringA", "LoadLibraryA"};
volatile FARPROC kept[3];
int main(void) {
  kept[0] = (FARPROC)&ReadFile;
  kept[1] = (FARPROC)&LoadLibraryA;
  kept[2] = (FARPROC)&CreateProcessA;
  return names[0][0] == 0;
}
