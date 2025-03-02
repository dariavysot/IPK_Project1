CXX = g++
CXXFLAGS = -std=c++17 -Wall -Wextra -pedantic

TARGET = ipk-l4-scan
SOURCES = ipk-l4-scan.cpp tcp-scanner.cpp
OBJECTS = $(SOURCES:.cpp=.o)

all: $(TARGET)

$(TARGET): $(OBJECTS)
	$(CXX) $(CXXFLAGS) -o $@ $^

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

clean:
	rm -f $(OBJECTS) $(TARGET)

.PHONY: all clean
