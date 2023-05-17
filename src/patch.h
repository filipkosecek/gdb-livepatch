#ifndef PATCH_H
#define PATCH_H

#include <stdint.h>
#include <string.h>

#define PATCH_SECTION_NAME "gdbpatch"

/* size constants */
#define PAGE_SIZE 4096
#define HEADER_SIZE 48
#define MAGIC_CONST 0x198E637F

/* variable attributes*/
#define PATCH_SECTION __attribute__((section(PATCH_SECTION_NAME)))
#define CONSTRUCTOR __attribute__((constructor))

/* patch strategy commands */
#define PATCH_OWN_LONG(orig, replace) "O:L:" #orig ":" #replace ";"
#define PATCH_OWN_SHORT(orig, replace) "O:S:" #orig ":" #replace ";"
#define PATCH_LIB(orig, replace) "L:N:" #orig ":" #replace ";"

/* patch metadata variables */
#define PATCH(__X) \
PATCH_SECTION char patch_commands[] = __X; \
\
PATCH_SECTION static char patch_header[HEADER_SIZE] __attribute__((section(PATCH_SECTION_NAME))) = {0}; \
CONSTRUCTOR void init(void); \
\
void init(void){ \
	uint32_t commands_len, magic_constant = MAGIC_CONST; \
\
	memcpy(patch_header, &magic_constant, sizeof(magic_constant)); \
	commands_len = (uint32_t) strlen(patch_commands); \
	memcpy(patch_header + (HEADER_SIZE - sizeof(commands_len)), &commands_len, sizeof(commands_len)); \
}

#endif
