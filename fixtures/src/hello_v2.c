// fixtures/src/hello_v2.c
// Bytasm test fixture, written for Bytasm. Never executed by Bytasm or its tests.
// Preserve v1's URL observation; add one explicit environment import and string.
int puts(const char *s);
char *getenv(const char *name);

int main(void) {
  puts("bytasm fixture v1: https://example.invalid/help");
  if (getenv("BYTASM_DEMO")) {
    puts("bytasm fixture v2: environment lookup");
  }
  return 0;
}
