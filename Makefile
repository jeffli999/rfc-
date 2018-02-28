CPP = gcc
CFLAGS = -g

rfc: rfc.c flow.c rfc.h flow.h
	${CPP} ${CFLAGS} -o rfc rfc.c flow.c

all: rfc 


