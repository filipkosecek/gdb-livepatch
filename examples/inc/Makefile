.PHONY: clean all

all: inc patch

inc: inc.c
	gcc -Wall -Werror -W -ggdb -o inc inc.c

patch: patch.c
	gcc -o patch.so patch.c -Wall -Werror -W -fPIC -shared -I../header/

clean:
	rm inc
	rm patch.so
