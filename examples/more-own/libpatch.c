#include "patch.h"

int new_x(int a) {
    return a * 2;
}

int new_y(int a) {
    return (!!a)^(++a);
}

PATCH(
    PATCH_OWN_SHORT(x, new_x)
    PATCH_OWN_SHORT(y, new_y)
    PATCH_OWN_SHORT(z, new_x)
)
