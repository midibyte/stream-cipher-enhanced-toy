# basic make file for alice and bob

CC := g++
CFLAGS := -Wall -std=c++11 -g
LIBS := -ltomcrypt -lzmq
DEPS := helper.h
# DEPS :=

all: alice bob

alice: alice.cpp $(DEPS)
	$(CC) $(CFLAGS) -o alice alice.cpp $(DEPS) $(LIBS)

bob: bob.cpp $(DEPS)
	$(CC) $(CFLAGS) -o bob bob.cpp $(DEPS) $(LIBS)


.PHONY: clean
clean: 
	-rm alice bob