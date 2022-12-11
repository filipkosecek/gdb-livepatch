.PHONY: clean all

all: patch_target patch

patch_target: test.c
	gcc -Wall -Werror -W -ggdb -o patch_target test.c

patch: patch.c
	gcc -o patch.so patch.c -Wall -Werror -W -fPIC -shared -I../header/

clean:
	rm patch_target
	rm patch.so
