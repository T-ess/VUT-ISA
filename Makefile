CC = g++
FLAGS = -g -c -Wall

all: client.o
	$(CC) -g client.o -o client $(LFLAGS)

client.o: client.cpp
	$(CC) $(FLAGS) client.cpp 

clean:
	rm -f client.o client