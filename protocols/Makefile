CXX=g++
CXXFLAGS+=-std=c++0x -c -Wall -Wextra -fPIC -O2
LDFLAGS+=-shared

SOURCES=ArpPacket.cpp call.cpp ICMPPacket.cpp \
        IPPacket.cpp TCPPacket.cpp UDPPacket.cpp

OBJECTS=$(SOURCES:.cpp=.o)
EXECUTABLE=libprotocols.so

all: $(SOURCES) $(EXECUTABLE)

debug: CXXFLAGS += -DDEBUG -g
debug: LDFLAGS += -DDEBUG -g
debug: $(SOURCES) $(EXECUTABLE)
		
$(EXECUTABLE): $(OBJECTS) 
	$(CXX) $(LDFLAGS) $(OBJECTS) -o $@ $(LIBS)

.cpp.o:
	$(CXX) $(CXXFLAGS) $< -o $@

clean:
	rm -f *.o $(EXECUTABLE)