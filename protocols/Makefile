CXX=g++
LTO_FLAGS=-flto -Bsymbolic-functions -fno-exceptions -fno-rtti
CXXFLAGS+=-std=c++0x -c -Wall -Wextra -fPIC -O2 $(LTO_FLAGS)
LDFLAGS+=-shared -ljsoncpp -flto $(LTO_FLAGS)

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