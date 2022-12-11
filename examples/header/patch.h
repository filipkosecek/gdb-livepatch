#ifndef PATCH_H
#define PATCH_H
#define PATCH(__X) const char patches[] __attribute__((section(".patch"))) = __X;
#define PATCH_OWN(orig, replace) "O" #orig "." #replace "\n"
#define PATCH_LIB(orig, replace) "L" #orig "." #replace "\n"
#endif
