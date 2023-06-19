#include <stdint.h>
#include "patch.h"

void dec(uint64_t *x) {
	*x -= 1;
}

PATCH(
	PATCH_OWN_SHORT(target_function, dec)
)
