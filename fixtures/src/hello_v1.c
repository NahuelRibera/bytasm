// fixtures/src/hello_v1.c
// Bytasm test fixture, written for Bytasm. Never executed by Bytasm or its tests.
//
// `puts` is declared here instead of including <stdio.h> so the same source can
// also be compiled into an x86-64 ELF object on a host with no Linux headers.
int puts(const char *s);

int main(void) {
  puts("bytasm fixture v1: https://example.invalid/help");
  return 0;
}
