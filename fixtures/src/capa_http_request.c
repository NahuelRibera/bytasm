// Self-authored static-analysis fixture. Never executed by Bytasm or its tests.
// Demonstrates only a statically referenced WinHTTP request-sending call site.
#include <windows.h>
#include <winhttp.h>
__attribute__((noinline)) static int fixture_send_request(HINTERNET request) {
  return WinHttpSendRequest(request, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                            WINHTTP_NO_REQUEST_DATA, 0, 0, 0) ? 0 : 1;
}
int main(void) { return fixture_send_request(NULL); }
