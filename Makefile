# basic make file for alice and bob

CC := g++
CFLAGS := -Wall
LIBS := -ltomcrypt -lzmq
# DEPS := helper.hpp
DEPS :=

all: alice bob

alice: alice.cpp
	$(CC) $(CFLAGS) -o alice alice.cpp $(DEPS) $(LIBS)

bob: bob.cpp
	$(CC) $(CFLAGS) -o bob bob.cpp $(DEPS) $(LIBS)
