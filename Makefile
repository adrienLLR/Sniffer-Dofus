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


# CC = gcc
# BIN = bin
# SRC = src
# INCLUDE_PATHS = include
# LIBRARY_PATHS = lib

# LIBRARIES   = -lpcap #-lpthread  #Don't forget that -l is the option
# SNIFFER  = sniffer
# SEND  = send
# MAIN = main
# CLIENT = client
# DATAPARSER = dataparser


# .PHONY:	clean all
# #Sert a régénérer les dépendances à chaque fois

# all: $(BIN)/$(SNIFFER).o $(BIN)/$(SEND).o $(BIN)/$(DATAPARSER).o $(BIN)/$(MAIN).o 
# 	$(CC) -o $(BIN)/$(MAIN) $^  -I$(INCLUDE_PATHS) -L$(LIBRARY_PATHS) $(LIBRARIES)

# sniff:	clean $(BIN)/$(SNIFFER)
# 	./$(BIN)/$(SNIFFER)

# main: clean all
# 	./$(BIN)/$(MAIN)

# client: clean $(BIN)/$(CLIENT)
# 	./$(BIN)/$(CLIENT)

# clean:	
# 	-rm $(BIN)/*


# $(BIN)/$(SNIFFER).o: $(SRC)/sniffer_libcap.c
# 	$(CC) -o $@ -c $^ -I$(INCLUDE_PATHS)

# $(BIN)/$(SEND).o: $(SRC)/sendpacket.c
# 	$(CC) -o $@ -c $^ -I$(INCLUDE_PATHS)

# $(BIN)/$(MAIN).o: $(SRC)/main.c
# 	$(CC) -o $@ -c $^ -I$(INCLUDE_PATHS)

# $(BIN)/$(DATAPARSER).o: $(SRC)/data_parser.c
# 	$(CC) -o $@ -c $^ -I$(INCLUDE_PATHS)

# $(BIN)/$(CLIENT): $(SRC)/clientside.c
# 	$(CC) $^ -o $@ -I$(INCLUDE_PATHS)


# all: library.cpp main.cpp
# In this case:
# $@ evaluates to all
# $< evaluates to library.cpp
# $^ evaluates to library.cpp main.cpp