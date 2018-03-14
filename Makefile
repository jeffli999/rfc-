CPP = gcc
CFLAGS = -g

rfc: rfc.c flow.c stats.c rfc.h flow.h stats.h
	${CPP} ${CFLAGS} -o rfc rfc.c flow.c stats.c

all: rfc 


