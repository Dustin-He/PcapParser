#include "parser.h"

int main(int argc, char *argv[]) {
	std::string input_path;
	std::string output_path;
	std::string config_file = "./parser.conf";
	std::unique_ptr<INIReader> config(new INIReader(config_file));
	// TODO: arguments
	if (argc < 2) {
		printf("Usage: ./parser input_path [output_path]");
		return 1;
	}

	int64_t packet_count = config->GetInteger("parser", "packet_count", -1);
	int64_t flow_count = config->GetInteger("parser", "flow_count", -1);
	int64_t epoch_num = config->GetInteger("parser", "epoch_num", -1);
	double epoch_len = config->GetReal("parser", "epoch_len", 1);
	bool write_to_binary_file = config->GetBoolean("parser", "write_to_binary_file", false);
	bool write_to_txt_file = config->GetBoolean("parser", "write_to_txt_file", false);
	bool write_to_pcap_file = config->GetBoolean("parser", "write_to_pcap_file", false);
	int key_len = config->GetInteger("parser", "key_len", 13);
	int val_type = config->GetInteger("parser", "val_type", 0);

	input_path = argv[1];
	if (argc > 2)
		output_path = argv[2];

	std::unique_ptr<Value> v_ptr(new Value(val_type));
	switch (key_len) {
		case 4:
		{
			Parser::PcapParser<4> pcap_parser(input_path.c_str(), output_path.c_str(), v_ptr, packet_count, write_to_binary_file,
												write_to_txt_file, write_to_pcap_file, flow_count, epoch_num, epoch_len);
			pcap_parser.pcapParse();
		}
		break;
		case 8:
		{
			Parser::PcapParser<8> pcap_parser(input_path.c_str(), output_path.c_str(), v_ptr, packet_count, write_to_binary_file,
												write_to_txt_file, write_to_pcap_file, flow_count, epoch_num, epoch_len);
			pcap_parser.pcapParse();
		}
		break;
		case 13:
		{
			Parser::PcapParser<13> pcap_parser(input_path.c_str(), output_path.c_str(), v_ptr, packet_count, write_to_binary_file,
												write_to_txt_file, write_to_pcap_file, flow_count, epoch_num, epoch_len);
			pcap_parser.pcapParse();
		}
		break;
		default:
		printf("Invalid key length\n");
		return -1;
	}
	

	return 0;
}