CXX = g++
CXXFLAGS = -std=c++17 -Wall -c
LXXFLAGS = -std=c++17
OBJECTS = main.o Logger.o Property.o Protocol.o
TARGET = main

$(TARGET): $(OBJECTS)
	$(CXX) $(LXXFLAGS) $(OBJECTS) -o $(TARGET) -lpcap -ljson-c -I "spdlog/include"
Logger.o: Logger.cpp Logger.h
	$(CXX) $(CXXFLAGS) Logger.cpp -I "spdlog/include"
Property.o: Property.cpp Property.h
	$(CXX) $(CXXFLAGS) Property.cpp
Protocol.o: Protocol.cpp Protocol.h
	$(CXX) $(CXXFLAGS) Protocol.cpp
main.o: main.cpp
	$(CXX) $(CXXFLAGS) main.cpp 
