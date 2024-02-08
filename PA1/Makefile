# Compiler
CXX = g++
# Compiler flags
CXXFLAGS = -std=c++11 -Wall -Wextra

# Source file
SRC = cipher.cpp
# Object files
OBJ = $(SRC:.cpp=.o)
# Executable binary
BIN = cipher

# Default target
all: $(BIN)

# Compile source file to object file
%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

# Link object files to generate executable binary
$(BIN): $(OBJ)
	$(CXX) $(CXXFLAGS) $(OBJ) -o $(BIN)

# Clean up generated files
clean:
	rm -f $(BIN) $(OBJ)
