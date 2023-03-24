#!/bin/make
OUTDIR	= ./build
TARGET	= $(OUTDIR)/curo
SOURCES	= $(wildcard *.cpp)
OBJECTS	= $(addprefix $(OUTDIR)/, $(SOURCES:.cpp=.o))
LIBCURO_SHARED = ../build/libcuro.so

CFLAGS = -I../

.PHONY: all
all: $(TARGET)

.PHONY: clean
clean:
	$(RM) $(OBJECTS) $(TARGET)

.PHONY: run
run: $(TARGET)
	./build/curo

$(TARGET): $(OBJECTS) Makefile
	$(CXX) $(CFLAGS) -o $(TARGET) $(OBJECTS) $(LIBCURO_SHARED)

$(OUTDIR)/%.o: %.cpp Makefile
	mkdir -p build
	$(CXX) $(CFLAGS) -o $@ -c $<
