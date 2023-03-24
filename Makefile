#!/bin/make
OUTDIR	= ./build
LIBCURO	= $(OUTDIR)/libcuro.so
SOURCES	= $(wildcard *.cpp)
OBJECTS	= $(addprefix $(OUTDIR)/, $(SOURCES:.cpp=.o))

CFLAGS = -shared -fPIC

PLATFORM = pf_packet

.PHONY: all
all: $(LIBCURO)

.PHONY: clean
clean:
	$(RM) $(OBJECTS) $(LIBCURO)

.PHONY: run
run: $(TARGET)
	make -C $(PLATFORM) run

$(LIBCURO): $(OBJECTS) Makefile
	$(CXX) $(CFLAGS) -o $(LIBCURO) $(OBJECTS) 

$(OUTDIR)/%.o: %.cpp Makefile
	mkdir -p build
	$(CXX) $(CFLAGS) -o $@ -c $<
