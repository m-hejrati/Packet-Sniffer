CXX = g++
CXXFLAGS = -std=c++17 -Wall -c
LXXFLAGS = -std=c++17
OBJECTS = main2.o Logger.o Property.o Protocol.o Session.o
TARGET = main2

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
main2.o: main2.cpp
	$(CXX) $(CXXFLAGS) main2.cpp -lpcap -ljson-c -I "spdlog/include"
