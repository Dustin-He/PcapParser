#include "parser.h"

int main(int argc, char *argv[]) {
	std::string input_path;
	std::string output_path;

	if (argc < 2) {
		printf("Usage: ./parser input_path [output_path]");
		return 1;
	}

	input_path = argv[1];
	if (argc > 2)
		output_path = argv[2];

	Parser::PcapParser<KEY_LEN, VAL_TYPE> pcap_parser(input_path.c_str(), output_path.c_str(), PACKET_COUNT, WRITE_TO_BINARY_FILE,
												WRITE_TO_TXT_FILE, FLOW_COUNT, EPOCN_NUM, EPOCH_LEN);

	pcap_parser.pcapParse();

	return 0;
}