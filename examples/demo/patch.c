#include "patch.h"
#include <stdint.h>
#include <stdio.h>

void mult(uint64_t *counter) {
	*counter *= 2;
}

int pretty_printer(const char *format, uint64_t x) {
	return printf("The current value is: %lu\n", x);
}

PATCH(
	PATCH_OWN_SHORT(target_function, mult)
	PATCH_LIB(printf, pretty_printer)
)
