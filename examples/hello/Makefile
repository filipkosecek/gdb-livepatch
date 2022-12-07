.PHONY: clean all

all: patch_target patch

patch_target: test.c
	gcc -Wall -Werror -W -ggdb -o test test.c

patch: patch.c
	gcc -Wall -W -fPIC -shared -o patch.so patch.c

clean:
	rm test
	rm patch.so
