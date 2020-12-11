CXX = g++
CXXFLAGS = -std=c++17 -Wall -c
LXXFLAGS = -std=c++17
OBJECTS = main.o Logger.o Property.o Protocol.o Session.o Engine.o Input.o
TARGET = main

$(TARGET): $(OBJECTS)
	$(CXX) $(LXXFLAGS) $(OBJECTS) -o $(TARGET) -lpcap -ljson-c -I "spdlog/include"
Logger.o: Engine/Logger.cpp Engine/Logger.h
	$(CXX) $(CXXFLAGS) "Engine/Logger.cpp" -I "spdlog/include"
Property.o: Engine/Property.cpp Engine/Property.h
	$(CXX) $(CXXFLAGS) "Engine/Property.cpp"
Protocol.o: Engine/Protocol.cpp Engine/Protocol.h
	$(CXX) $(CXXFLAGS) "Engine/Protocol.cpp"
Session.o: Engine/Session.cpp Engine/Session.h
	$(CXX) $(CXXFLAGS) "Engine/Session.cpp"
Engine.o: Engine/Engine.cpp Engine/Engine.h
	$(CXX) $(CXXFLAGS) "Engine/Engine.cpp" -I "spdlog/include"
Input.o: Input/Input.cpp Input/Input.h
	$(CXX) $(CXXFLAGS) "Input/Input.cpp" -ljson-c
main.o: main.cpp
	$(CXX) $(CXXFLAGS) main.cpp -lpcap -ljson-c -I "spdlog/include"
