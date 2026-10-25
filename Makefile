# SPDX-License-Identifier: MIT
# Copyright (c) 1993-1994, 2026 Andy van Wezel

CXX      ?= g++
CXXFLAGS ?= -O2 -Wall -Wextra

SRCS     := $(filter-out src/main.cpp,$(wildcard src/*.cpp))
OBJS     := $(SRCS:src/%.cpp=obj/%.o)

odette: obj/main.o $(OBJS)
	$(CXX) $(CXXFLAGS) -o $@ $^

test/test_primitives: test/test_primitives.cpp $(OBJS)
	$(CXX) $(CXXFLAGS) -Isrc -o $@ $^

obj/%.o: src/%.cpp
	@mkdir -p obj
	$(CXX) $(CXXFLAGS) -MMD -MP -c -o $@ $<

-include obj/*.d

test: odette test/test_primitives
	./test/test_primitives
	bash test/test.sh

clean:
	rm -rf obj odette test/test_primitives

.PHONY: test clean
