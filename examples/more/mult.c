#include <stdint.h>
#include "patch.h"

void mult(uint64_t *x){
	*x *= 2;
}

PATCH(
	PATCH_OWN(target_function, mult)
)
