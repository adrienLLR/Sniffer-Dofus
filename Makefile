CC=gcc
CFLAGS=-Iinclude
LDFLAGS=-lpcap

SOURCES=$(wildcard src/*.c)
OBJECTS=$(SOURCES:src/%.c=bin/%.o)

EXECUTABLE=bin/main

all: $(EXECUTABLE)
	./$(EXECUTABLE)

$(EXECUTABLE): $(OBJECTS)
	$(CC) $(CFLAGS) $^ $(LDFLAGS) -o $@

bin/%.o: src/%.c
	$(CC) $(CFLAGS) -c $< -o $@

.PHONY: clean

clean:
	rm -f $(OBJECTS) $(EXECUTABLE)
