#!/bin/make
OUTDIR	= ./build
SOURCES	= $(wildcard *.cpp)
OBJECTS	= $(addprefix $(OUTDIR)/, $(SOURCES:.cpp=.o))

STATIC_LIB	= $(OUTDIR)/libcuro.a
SHARED_LIB	= $(OUTDIR)/libcuro.so

CFLAGS = -fPIC

PLATFORM = pf_packet

.PHONY: all
all: $(STATIC_LIB) $(SHARED_LIB)

.PHONY: static
static: $(STATIC_LIB)

.PHONY: shared
shared: $(SHARED_LIB)

.PHONY: clean
clean:
	$(RM) $(OBJECTS) $(LIBCURO)

.PHONY: run
run: $(TARGET)
	make -C $(PLATFORM) run

$(STATIC_LIB): $(OBJECTS) Makefile
	$(AR) rcs $(STATIC_LIB) $(OBJECTS) 

$(SHARED_LIB): $(OBJECTS) Makefile
	$(CXX) $(CFLAGS) -shared -o $(SHARED_LIB) $(OBJECTS) 


$(OUTDIR)/%.o: %.cpp Makefile
	mkdir -p build
	$(CXX) $(CFLAGS) -o $@ -c $<
