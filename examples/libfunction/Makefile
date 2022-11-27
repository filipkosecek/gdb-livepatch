.PHONY: all clean

all: test patch.so

patch.so: patchlib/patch.c
	gcc -fPIC -Wall -Werror -W -shared -o patch.so patchlib/patch.c

test: target/target.c
	gcc -Wall -Werror -W -ggdb -o test target/target.c

clean:
	rm test
	rm patch.so
