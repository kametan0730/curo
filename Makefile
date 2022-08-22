OUTDIR	= ./build
TARGET	= $(OUTDIR)/curo
SOURCES	= $(wildcard *.cpp)
OBJECTS	= $(addprefix $(OUTDIR)/, $(SOURCES:.cpp=.o))

.PHONY: all
all: $(TARGET)

.PHONY: clean
clean:
	rm -rf $(OBJECTS) $(TARGET)

$(TARGET): $(OBJECTS) Makefile
	$(CXX) -o $(TARGET) $(OBJECTS)

$(OUTDIR)/%.o: %.cpp Makefile
	mkdir -p build
	$(CXX) -o $@ -c $<
