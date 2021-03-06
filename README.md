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
network_endian = false		# The endian of the flow keys(false means converting flow keys to the machine endian)
key_len = 13			# The length of the flow keys, only 4(1-tuple), 8(2-tuple), 13(5-tuple) is permitted
val_timestamp = 1		# Whether to include packet timestamp in the value
val_length = 1			# Whether to include packet length in the value

# input file path(" is not needed)
input_path = input_pcap_file
# output file path
output_path = output_file
```



### Analyze the trace

If you just need to analyze the file, but not to generate a new file, you have two options:

+ Comment the output path with `#` or `;`
+ Make the above three output format options `false`



### Format of the binary file

#### Flow key

+ 1-tuple: ip.src
+ 2-tuple: ip.src  ip.dst
+ 5-tuple: ip.src  ip.dst  src_port  dst_port  ip.protocol

#### Value

**The values are already in machine endian.**

**The value is put after the flow key, if any value is needed.**

Timestamp is a (4+4)-byte value. The significant 32 bits represent seconds, the others represent microseconds/nanseconds.

Length is a 2-byte value.

If both are required, than the value of timestamp is put before the value of length.

### Format of the txt file

The format is similar as that of the binary file, but we convert every fields into a string.

### TODO

To support 802.3
