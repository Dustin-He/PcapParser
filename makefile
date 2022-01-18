parser: parser.cpp parser.h util.h PacketHeader.h value.h FlowKey.h parameters.h
	g++ -std=c++14 -O2 parser.cpp -o parser

clean:
	rm parser