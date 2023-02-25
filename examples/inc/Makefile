.PHONY: clean all

all: inc patch

inc: inc.c
	gcc -Wall -Werror -W -o inc inc.c

patch: patch.c
	gcc -g -o patch.so patch.c -Wall -Werror -W -fPIC -shared -I../../src/

clean:
	rm inc
	rm patch.so
