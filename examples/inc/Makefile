.PHONY: clean all

all: patch_target patch

patch_target: target/test.c
	gcc -Wall -Werror -W -ggdb -o patch_target target/test.c

patch: patchlib/patch.c
	gcc -Wall -Werror -W -shared -o patch.so patchlib/patch.c

clean:
	rm patch_target
	rm patch.so
