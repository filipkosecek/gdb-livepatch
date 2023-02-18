#include <stdint.h>
#include "patch.h"

void patch_function(uint64_t *x){
	*x *= 2;
}

PATCH(
	PATCH_OWN(target_function, patch_function)
)
