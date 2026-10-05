/* Signed TEST candidate: offline-compatible; its platform start deliberately
 * fails. */
#include <stdio.h>
#include <string.h>
int main(int argc, char **argv) {
  if (argc != 2)
    return 2;
  if (!strcmp(argv[1], "--release-id")) {
    puts("legacy-test-new");
    return 0;
  }
  if (!strcmp(argv[1], "--self-check"))
    return 0;
  if (!strcmp(argv[1], "--boot-protocol")) {
    puts("1");
    return 0;
  }
  return 2;
}
