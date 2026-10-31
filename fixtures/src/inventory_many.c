/* Self-authored static inventory fixture. Compile only; never execute. */
/* Four hundred named functions exercise inventory beyond the former 256 cap. */
#define FUNCTION(group, n) \
    __attribute__((noinline, used)) int inventory_##group##_##n(void) { return n; }
#define GROUP(group) \
    FUNCTION(group, 0) FUNCTION(group, 1) FUNCTION(group, 2) FUNCTION(group, 3) \
    FUNCTION(group, 4) FUNCTION(group, 5) FUNCTION(group, 6) FUNCTION(group, 7) \
    FUNCTION(group, 8) FUNCTION(group, 9)
GROUP(00) GROUP(01) GROUP(02) GROUP(03) GROUP(04)
GROUP(05) GROUP(06) GROUP(07) GROUP(08) GROUP(09)
GROUP(10) GROUP(11) GROUP(12) GROUP(13) GROUP(14)
GROUP(15) GROUP(16) GROUP(17) GROUP(18) GROUP(19)
GROUP(20) GROUP(21) GROUP(22) GROUP(23) GROUP(24)
GROUP(25) GROUP(26) GROUP(27) GROUP(28) GROUP(29)
GROUP(30) GROUP(31) GROUP(32) GROUP(33) GROUP(34)
GROUP(35) GROUP(36) GROUP(37) GROUP(38) GROUP(39)
int main(void) { return inventory_00_0(); }
