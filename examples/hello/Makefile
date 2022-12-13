.PHONY: clean all

all: hello patch

hello: hello.c
	gcc -Wall -Werror -W -ggdb -o hello hello.c

patch: patch.c
	gcc -Wall -W -fPIC -shared -o patch.so patch.c -I../header/

clean:
	rm hello
	rm patch.so
