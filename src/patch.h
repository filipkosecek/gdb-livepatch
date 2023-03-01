#ifndef PATCH_H

#include <stdint.h>
#include <string.h>

#define PATCH_H
#define PAGE_SIZE 4096
#define HEADER_SIZE 32
#define LOG_SIZE 2*(PAGE_SIZE)
#define MAGIC_CONST 153823877865751

#define PATCH_OWN(orig, replace) "O:" #orig ":" #replace ";"
#define PATCH_LIB(orig, replace) "L:" #orig ":" #replace ";"

#define PATCH(__X) \
static char patch_header[HEADER_SIZE] __attribute__((section(".patch"))) = {0}; \
static char patch_commands[] __attribute__((section(".patch"))) = __X; \
__attribute__((unused)) static char patch_log[LOG_SIZE] __attribute__((section(".patch"))) = {0}; \
__attribute__((unused)) static char patch_backup[PAGE_SIZE] __attribute__((section(".patch"))) = {0}; \
\
__attribute__((constructor)) static void lib_init(void){ \
	uint64_t magic_constant = MAGIC_CONST; \
	uint32_t commands_len; \
\
	memcpy(patch_header, &magic_constant, sizeof(magic_constant)); \
	commands_len = (uint32_t) strlen(patch_commands); \
	memcpy(patch_header + (HEADER_SIZE - sizeof(commands_len)), &commands_len, sizeof(commands_len)); \
}

#endif
