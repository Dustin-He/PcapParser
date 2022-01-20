# PcapParser: A powerful PCAP parser for OmniSketch

### Two main functions of this tool

+ Make your own data with specified flow keys and values
+ Extract the packets and generate a new pcap file



### Usage

```shell
make
./parser [-h]([--help]) [-c config_file]([--config_file config_file])
```



### Config

The config file is `parser.conf`. 

Of course, you can write your own config file with `parser.conf` as a template and use `-c` option to specify the config file path.

Here is the config file template, read it first:

```
[parser]			# This line is always needed

packet_count = 10000		# Number of packets(TCP/UDP) to parse, -1 means all the packets
flow_count = -1			# Number of flows to parse, -1 means all the flows
epoch_num = -1			# Number of epochs to parse, -1 means all the epochs
epoch_len = 1			# The length of an epoch(second)
write_to_binary_file = false	# To specify the format of the output file (binary file)
write_to_txt_file = true	# To specify the format of the output file (txt file)
write_to_pcap_file = false	# To specify the format of the output file (pcap file), extract packets to generate a new pcap file
network_endian = false	# The endian of the flow keys
key_len = 13			# The length of the flow keys, only 4(1-tuple), 8(2-tuple), 13(5-tuple) is permitted
val_timestamp = 1		# Whether to include packet timestamp in the value
val_length = 1			# Whether to include packet length in the value

# input file path
input_path = /Users/hejintao/Desktop/parser/CAIDA_data/equinix-nyc.dirA.20180315-130000.UTC.anon.pcap
# output file path
output_path = ./data.txt
```



### Analyze the trace

If you just need to analyze the file, but not to generate a new file, you have two options:

+ Comment the output path with `#` or `;`
+ Make the above three output format options `false`
