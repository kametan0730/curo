#!/bin/make
OUTDIR	= ./build
TARGET	= $(OUTDIR)/libcuro.so
SOURCES	= $(wildcard *.cpp)
OBJECTS	= $(addprefix $(OUTDIR)/, $(SOURCES:.cpp=.o))

CFLAGS = -shared -fPIC

.PHONY: all
all: $(TARGET)

.PHONY: clean
clean:
	$(RM) $(OBJECTS) $(TARGET)

.PHONY: run
run: $(TARGET)
	./build/curo

$(TARGET): $(OBJECTS) Makefile
	$(CXX) -shared -fPIC -o $(TARGET) $(OBJECTS) 

$(OUTDIR)/%.o: %.cpp Makefile
	mkdir -p build
	$(CXX) -fPIC -o $@ -c $<
