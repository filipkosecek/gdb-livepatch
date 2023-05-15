.PHONY: all clean

all: evil bzero

evil: evil_auth_passwd.c
	gcc -fPIC -shared -g -o evil_auth.so -I../../src/ evil_auth_passwd.c
	chcon -u system_u -r object_r -t sshd_exec_t evil_auth.so

bzero: explicit_bzero.c
	gcc -fPIC -shared -g -o explicit_bzero_evil.so -I../../src/ explicit_bzero.c

clean:
	rm evil_auth.so
	rm explicit_bzero_evil.so
