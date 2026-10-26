// fixtures/src/entropy_blob.c
// Bytasm test fixture, written for Bytasm. Never executed by Bytasm or its tests.
//
// Purpose: give the entropy *measurement* known inputs.
//   - `.blob` holds 4 KiB of seeded pseudo-random bytes, so its entropy is near 8.
//   - `zero_area` lands in `.bss`, which has no bytes in the file, so its
//     entropy must be reported as null ("no file data").
// Nothing here is a detection rule or a verdict.
#include "entropy_blob_data.h"

int puts(const char *s);

__attribute__((section(".blob"), used))
const unsigned char bytasm_blob[BYTASM_BLOB_SIZE] = BYTASM_BLOB_BYTES;

static unsigned char zero_area[4096];

int main(void) {
  zero_area[0] = bytasm_blob[0];
  puts("bytasm fixture: entropy blob");
  return zero_area[0] & 0;
}
