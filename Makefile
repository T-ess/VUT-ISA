CC = g++
FLAGS = -g -c -Wall

all: client.o base64.o
	$(CC) -g client.o base64.o -o client $(LFLAGS)

client.o: client.cpp
	$(CC) $(FLAGS) client.cpp 

base64.o: base64.cpp
	$(CC) $(FLAGS) base64.cpp 

clean:
	rm -f client.o base64.o client