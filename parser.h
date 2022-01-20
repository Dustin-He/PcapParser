#ifndef PARSER_H
#define PARSER_H

#include "util.h"

namespace Parser{

// TODO: flow count
template<int flowkey_len>
class PcapParser {
    /* Pcap header & all packet headers */
    PacketHeader::PcapFileHeader pcap_header;
    PacketHeader::PcapPacketHeader packet_header;
    PacketHeader::FrameHeader eth_header;
    PacketHeader::IPHeader ip_header;
    PacketHeader::TCPHeader tcp_header;
    PacketHeader::UDPHeader udp_header;

    /* Arguments to define the parser behaviors */
    bool to_binary_file, to_txt_file, contain_eth_header, to_pcap_file, network_endian;
    FILE *input, *output;
    int64_t packet_offset;
    int64_t packet_cnt, flow_cnt, epoch_num, current_epoch, total_packets, total_flows;
    double epoch_length;

    /* For statistics */
    SketchLab::FlowKey<flowkey_len> key_content;
    std::unique_ptr<PcapValue::Value> value_content;
    PacketHeader::TimeVal start_time;
    bool first_packet;
    char buffer[BUFFER_LEN];
    PacketStatistics::PacketStatistics ps;
    std::map<SketchLab::FlowKey<flowkey_len>, uint32_t> flow_map;
    std::set<SketchLab::FlowKey<flowkey_len>> flow_set;

    /* Util functions */
    void calculateDistribution(std::map<double, uint32_t> &distr, double sz) const;
    double calculateExpectation(std::map<double, uint32_t> &distr) const;
    double calculateSkewness() const;
    inline uint64_t convertEndianD(uint64_t x) const;
    inline uint32_t convertEndianL(uint32_t x) const;
    inline uint16_t convertEndianS(uint16_t x) const;

    /* Output Functions */
    void fillFlowKey();
    void fillValue();
    inline void pcapWritePacketBinary(SketchLab::FlowKey<flowkey_len> k, std::unique_ptr<PcapValue::Value> &v) const ;
    inline void pcapWritePacketText(SketchLab::FlowKey<flowkey_len> k, std::unique_ptr<PcapValue::Value> &v) const ;
    inline void pcapWritePacketPcap() const ;

    /* Read Functions */
    int pcapReadPacket();
    
public:
    PcapParser(const char *input_path, const char *output_path, std::unique_ptr<PcapValue::Value> &v_ptr, int64_t pkt_cnt = -1,
                                    bool binary_file = false, bool txt_file = false, bool pcap_file = false,
                                    int64_t fl_cnt = -1, int64_t ep_num = -1, double ep_len = 1, bool net_en = false);

    ~PcapParser();

    int pcapParse();

};

template<int flowkey_len>
void PcapParser<flowkey_len>::calculateDistribution(std::map<double, uint32_t> &distr, double sz) const {
    std::map<double, uint32_t>::iterator map_iter;
    map_iter = distr.find(sz);
    if (map_iter != distr.end()) {
        map_iter->second += 1;
    }
    else {
        distr[sz] = 1;
    }
}

template<int flowkey_len>
double PcapParser<flowkey_len>::calculateExpectation(std::map<double, uint32_t> &distr) const {
    double sum = 0;
    double ret = 0;
    for (auto iter = distr.begin(); iter != distr.end(); ++iter) {
        sum += iter->second;
    }
    for (auto iter = distr.begin(); iter != distr.end(); ++iter) {
        ret += iter->first * iter->second / sum;
    }
    return ret;
}

template<int flowkey_len>
double PcapParser<flowkey_len>::calculateSkewness() const {
    std::map<double, uint32_t> distribution1;
    std::map<double, uint32_t> distribution2;
    std::map<double, uint32_t> distribution3;

    for (auto iter = flow_map.begin(); iter != flow_map.end(); ++iter) {
        calculateDistribution(distribution1, (double)iter->second);
        calculateDistribution(distribution2, (double)iter->second * iter->second);
        calculateDistribution(distribution3, (double)iter->second * iter->second * iter->second);
    }

    double expectation1 = calculateExpectation(distribution1);
    double expectation2 = calculateExpectation(distribution2);
    double expectation3 = calculateExpectation(distribution3);

    return (expectation3 - 3 * expectation1 * expectation2 + 2 * expectation1 * expectation1 * expectation1) / pow(expectation2 - expectation1 * expectation1, 1.5);
}

template<int flowkey_len>
uint64_t PcapParser<flowkey_len>::convertEndianD(uint64_t x) const {
    if (!network_endian) {
        return ntohll(x);
    }
    return x;
}

template<int flowkey_len>
uint32_t PcapParser<flowkey_len>::convertEndianL(uint32_t x) const {
    if (!network_endian) {
        return ntohl(x);
    }
    return x;
}

template<int flowkey_len>
uint16_t PcapParser<flowkey_len>::convertEndianS(uint16_t x) const {
    if (!network_endian) {
        return ntohs(x);
    }
    return x;
}

template<int flowkey_len>
void PcapParser<flowkey_len>::fillFlowKey() {
    uint32_t ip_src = convertEndianL(ip_header.src_ip);
    uint32_t ip_dst = convertEndianL(ip_header.dst_ip);
    uint16_t port_src, port_dst;

    switch (ip_header.protocol) {
        case PROTOCOL_TCP:
        port_src = convertEndianS(tcp_header.src_port);
        port_dst = convertEndianS(tcp_header.dst_port);
        break;
        case PROTOCOL_UDP:
        port_src = convertEndianS(udp_header.src_port);
        port_dst = convertEndianS(udp_header.dst_port);
        break;
        default:
        break;
    }

    switch (flowkey_len) {
        case 4:
        key_content.copy(0, SketchLab::FlowKey<4>(ip_src).cKey(), 4);
        break;
        case 8:
        key_content.copy(0, SketchLab::FlowKey<8>(ip_src, ip_dst).cKey(), 8);
        break;
        case 13:
        if (ip_header.protocol == PROTOCOL_TCP)
            key_content.copy(0, SketchLab::FlowKey<13>(ip_src, ip_dst, port_src, port_dst, ip_header.protocol).cKey(), 13);
        else if (ip_header.protocol == PROTOCOL_UDP)
            key_content.copy(0, SketchLab::FlowKey<13>(ip_src, ip_dst, port_src, port_dst, ip_header.protocol).cKey(), 13);
        break;
        default:
        break;
    }
}

template<int flowkey_len>
void PcapParser<flowkey_len>::fillValue() {
    switch (value_content->scheme) {
        case 0:
        break;
        case 1:
        value_content->time_stamp = packet_header.time_stamp;
        break;
        case 2:
        value_content->length = ntohs(ip_header.total_len);
        break;
        case 3:
        value_content->time_stamp = packet_header.time_stamp;
        value_content->length = ntohs(ip_header.total_len);
        break;
        default:
        break;
    }
}

template<int flowkey_len>
void PcapParser<flowkey_len>::pcapWritePacketBinary(SketchLab::FlowKey<flowkey_len> k, std::unique_ptr<PcapValue::Value> &v) const {
    fwrite(key_content.cKey(), flowkey_len, 1, output);
}

template<int flowkey_len>
void PcapParser<flowkey_len>::pcapWritePacketText(SketchLab::FlowKey<flowkey_len> k, std::unique_ptr<PcapValue::Value> &v) const {

}

template<int flowkey_len>
void PcapParser<flowkey_len>::pcapWritePacketPcap() const {
    uint32_t pcap_data_len = packet_header.caplen + PCAP_PKT_HEADER_LENGTH;
    assert(pcap_data_len <= BUFFER_LEN);
    fwrite(buffer, pcap_data_len, 1, output);
}

template<int flowkey_len>
int PcapParser<flowkey_len>::pcapReadPacket() {
    //读pcap数据包头结构
    if (fread(&packet_header, 16, 1, input) != 1) {
        printf("Can not read packet_header\n");
        return 1;
    }

    if (first_packet) {
        first_packet = false;
        start_time = packet_header.time_stamp;
    }
    double usec_delta = (double)packet_header.time_stamp.tv_usec - start_time.tv_usec;
    double sec_delta = packet_header.time_stamp.tv_sec - start_time.tv_sec;
    if (sec_delta + usec_delta * 1e-6 >= epoch_length) {
        // std::cout << sec_delta << " " << usec_delta <<  " " << sec_delta + usec_delta * 1e-6 << " " << epoch_length <<  std::endl;
        start_time = packet_header.time_stamp;
        if (current_epoch == epoch_num - 1) {
            return 2;
        }
        ps.flow_num[current_epoch] = flow_set.size();
        ps.packet_num.push_back(0);
        ps.total_len.push_back(0);
        ps.flow_num.push_back(0);
        flow_set.clear();
        current_epoch++;
    }

    if (total_packets >= packet_cnt && packet_cnt != -1) {
        return 3;
    }

    memcpy(buffer, &packet_header, sizeof(packet_header));

    if (fread(buffer + sizeof(packet_header), packet_header.caplen, 1, input) != 1) {
        printf("Can not read the packet\n");
        return 1;
    }

    uint32_t offset = sizeof(packet_header);

    if (contain_eth_header) {
        memcpy(&eth_header, buffer + offset, sizeof(eth_header));
        offset += sizeof(eth_header);
    }

    memcpy(&ip_header, buffer + offset, sizeof(ip_header));
    offset += sizeof(ip_header);

    /* ip头前4位为版本号, ipv4的为4，ipv6的为6 */
    uint8_t ip_ver = (ip_header.ver_hlen >> 4) & (0b00001111);
    bool other_packet = false;
    switch (ip_ver) {
        case 4: {
            if (ip_header.protocol == PROTOCOL_TCP && packet_header.caplen > offset - sizeof(packet_header)) {
                memcpy(&tcp_header, buffer + offset, sizeof(tcp_header));
                total_packets += 1;
                offset += sizeof(tcp_header);
            }
            else if (ip_header.protocol == PROTOCOL_UDP && packet_header.caplen > offset - sizeof(packet_header)){
                memcpy(&udp_header, buffer + offset, sizeof(udp_header));
                total_packets += 1;
                offset += sizeof(udp_header);
            }
            else {
                other_packet = true;
            }
            break;
        }
        default: {
            other_packet = true;
            break;
        }
    }

    packet_offset += PCAP_PKT_HEADER_LENGTH + packet_header.caplen;
    if (other_packet) return 4;
    return 0;
}

template<int flowkey_len>
PcapParser<flowkey_len>::PcapParser(const char *input_path, const char *output_path, std::unique_ptr<PcapValue::Value> &v_ptr, int64_t pkt_cnt,
                                    bool binary_file, bool txt_file, bool pcap_file,
                                    int64_t fl_cnt, int64_t ep_num, double ep_len, bool net_en)
{
    packet_cnt = pkt_cnt;
    flow_cnt = fl_cnt;
    epoch_num = ep_num;
    epoch_length = ep_len;
    network_endian = net_en;
    current_epoch = total_packets = total_flows = 0;
    packet_offset = 24;
    first_packet = true;
    value_content = std::move(v_ptr);
    input = fopen(input_path, "rb");
    
    if (output_path[0] != 0 && (binary_file || txt_file || pcap_file)) {
        output = fopen(output_path, "w");
        to_binary_file = binary_file;
        to_txt_file = txt_file;
        to_pcap_file = pcap_file;
    }
    else {
        output = NULL;
        to_binary_file = to_txt_file = to_pcap_file = false;
    }
    flow_set.clear();
    memset(buffer, 0, BUFFER_LEN);
}

template<int flowkey_len>
PcapParser<flowkey_len>::~PcapParser() {
    fclose(input);
    if (output != NULL)
        fclose(output);
}

template<int flowkey_len>
int PcapParser<flowkey_len>::pcapParse() {
    fseek(input, 0, SEEK_SET);
    if (fread(&pcap_header, PCAP_HEADER_LENGTH, 1, input) != 1) {
        printf("Can not read pcap header\n");
        return 1;
    }
    if (to_pcap_file) {
        fwrite(&pcap_header, PCAP_HEADER_LENGTH, 1, output);
    }
    contain_eth_header = (pcap_header.linktype == CONTAIN_ETH);
    // Read packets
    int ret = 0;
    while ((ret = fseek(input, packet_offset, SEEK_SET)) == 0) {
        /* Read a packet and make statistics */
        ret = pcapReadPacket();
        if (ret != 0 && ret != 4)
            break;
        else if (ret == 0) {
            fillFlowKey();
            fillValue();
            ps.packet_num[current_epoch]++;
            ps.total_len[current_epoch] += ntohs(ip_header.total_len);
            typename std::map<SketchLab::FlowKey<flowkey_len>, uint32_t>::iterator map_iter = flow_map.find(key_content);
            if (map_iter != flow_map.end()) {
                map_iter->second += 1;
            }
            else {
                flow_map[key_content] = 1;
            }
            flow_set.emplace(key_content);
        }
        else {
            continue;
        }
        if (to_binary_file) {
            pcapWritePacketBinary(key_content, value_content);
        }
        else if (to_txt_file) {
            pcapWritePacketText(key_content, value_content);
        }
        else if (to_pcap_file) {
            pcapWritePacketPcap();
        }
    }

    ps.flow_num[current_epoch] = flow_set.size();
    ps.skewness = calculateSkewness();
    std::cout << ps;
    return 0;
}

}

#endif