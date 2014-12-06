CXX=g++
CXXFLAGS+=-std=c++0x -c -Wall -Wextra -fPIC -O2
LDFLAGS+=-shared -ljsoncpp

SOURCES=call.cpp ArpPacket.cpp ICMPPacket.cpp \
        IPPacket.cpp TCPPacket.cpp UDPPacket.cpp \
        DNSPacket.cpp IPv6Packet.cpp VRRPPacket.cpp \
        PacketJson.cpp

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