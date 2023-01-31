#ifndef PATCH_H
#define PATCH_H
#define PAGE_SIZE 4096
#define PATCH(__X) const char patches[] __attribute__((section(".patch"))) = __X; \
char backup[PAGE_SIZE] __attribute__((section(".patch.backup"))) = {0};
#define PATCH_OWN(orig, replace) "O:" #orig ":" #replace
#define PATCH_LIB(orig, replace) "L:" #orig ":" #replace
#endif
