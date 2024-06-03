# Simona Ceskova xcesko00
# 30.04.2024
# KRY 2

CC=g++
CFLAGS=-g -Wall -fsanitize=address,leak

all: kry

kry: kry.o
	$(CC) $(CFLAGS) kry.o -o kry

kry.o: kry.cpp
	$(CC) $(CFLAGS) -c -o kry.o kry.cpp

clean:
	rm -f *.o kry