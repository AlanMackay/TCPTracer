#makefile for project 2

.c.o:
	gcc -g -c $?

all: tcptracer

# compile A2 
tcptracer: tcptracer.o
	gcc -Wall -g -o tcptracer tcptracer.o -lpcap

