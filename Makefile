CXX = g++
CXXFLAGS = -std=c++17 -Wall -c
LXXFLAGS = -std=c++17
OBJECTS = main.o Logger.o Property.o Protocol.o Session.o Engine.o Input.o
TARGET = main

$(TARGET): $(OBJECTS)
	$(CXX) $(LXXFLAGS) $(OBJECTS) -o $(TARGET) -lpcap -ljson-c -I "spdlog/include"
Logger.o: Logger.cpp Logger.h
	$(CXX) $(CXXFLAGS) Logger.cpp -I "spdlog/include"
Property.o: Property.cpp Property.h
	$(CXX) $(CXXFLAGS) Property.cpp
Protocol.o: Protocol.cpp Protocol.h
	$(CXX) $(CXXFLAGS) Protocol.cpp
Session.o: Session.cpp Session.h
	$(CXX) $(CXXFLAGS) Session.cpp
Engine.o: Engine.cpp Engine.h
	$(CXX) $(CXXFLAGS) Engine.cpp -I "spdlog/include"
Input.o: Input.cpp Input.h
	$(CXX) $(CXXFLAGS) Input.cpp -ljson-c
main.o: main.cpp
	$(CXX) $(CXXFLAGS) main.cpp -lpcap -ljson-c -I "spdlog/include"
