#include "parser.h"

int main(int argc, char *argv[]) {
	std::string config_file = "parser.conf";

	option options[] = {{"config_file", required_argument, nullptr, 'c'},
						{"help", no_argument, nullptr, 'h'}};

	int opt;
	while ((opt = getopt_long(argc, argv, "c:h", options, nullptr)) != -1) {
		switch(opt) {
			case 'c':
			config_file = optarg;
			break;
			case 'h':
			printf("Usage: ./parser [-h] [-c config_file]([--config_file config_file])\n");
			exit(0);
			default:
			break;
		}
	}

	std::unique_ptr<INIReader> config(new INIReader(config_file));

	int64_t packet_count = config->GetInteger("parser", "packet_count", -1);
	int64_t flow_count = config->GetInteger("parser", "flow_count", -1);
	int64_t epoch_num = config->GetInteger("parser", "epoch_num", -1);
	double epoch_len = config->GetReal("parser", "epoch_len", 1);
	bool write_to_binary_file = config->GetBoolean("parser", "write_to_binary_file", false);
	bool write_to_txt_file = config->GetBoolean("parser", "write_to_txt_file", false);
	bool write_to_pcap_file = config->GetBoolean("parser", "write_to_pcap_file", false);
	bool network_endian = config->GetBoolean("parser", "network_endian", false);
	int key_len = config->GetInteger("parser", "key_len", 13);
	int val_timestamp = config->GetInteger("parser", "val_timestamp", 0);
	int val_length = config->GetInteger("parser", "val_length", 0);
	std::string input_path = config->Get("parser", "input_path", "");
	std::string output_path = config->Get("parser", "output_path", "");

	int val_type = ((1?val_timestamp:0) << (PcapValue::ValueScheme::VAL_TIMESTAMP)) + ((1?val_length:0) << (PcapValue::ValueScheme::VAL_LENGTH));

	std::unique_ptr<PcapValue::Value> v_ptr(new PcapValue::Value(val_type));
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