#ifndef _UTIL_H
#define _UTIL_H

#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <iostream>
#include <iomanip>
#include <set>
#include <map>
#include <vector>
#include <numeric>
#include <algorithm>
#include <cassert>
#include <string>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "PacketHeader.h"
#include "FlowKey.h"
#include "value.h"
// #include "parameters.h"
#include "INIReader.h"
#include "getopt.h"

#define PROTOCOL_TCP 0x6
#define PROTOCOL_UDP 0x11

#define CONTAIN_ETH 0x00000001

#define PCAP_HEADER_LENGTH 24
#define PCAP_PKT_HEADER_LENGTH 16

#define VECTOR_LENGTH 60
#define BUFFER_LEN 10005

namespace PacketStatistics {

class PacketStatistics {
public:
    std::vector<uint32_t> flow_num, packet_num, total_len;
    double skewness;

    PacketStatistics() {
        flow_num.push_back(0);
        packet_num.push_back(0);
        total_len.push_back(0);
        skewness = 0;
    }

    friend std::ostream & operator << (std::ostream &outs, const PacketStatistics & ps); 
};

std::ostream & operator << (std::ostream &outs, const PacketStatistics & ps) {
    outs << std::setiosflags(std::ios::fixed) << std::setprecision(6);
    outs << "\e[31mFlow Number:\e[0m\n";
    for (auto iter = ps.flow_num.begin(); iter != ps.flow_num.end(); ++iter)
        outs << *iter << " ";
    outs << "\e[35mavg: \e[0m" << std::accumulate(std::begin(ps.flow_num), std::end(ps.flow_num), 0.0) / ps.flow_num.size();
    outs << "\e[35m max: \e[0m" << *std::max_element(ps.flow_num.begin(), ps.flow_num.end());
    outs << "\e[35m min: \e[0m" << *std::min_element(ps.flow_num.begin(), ps.flow_num.end()) << std::endl;

    outs << "\e[31mPacket Number:\e[0m\n";
    for (auto iter =  ps.packet_num.begin(); iter != ps.packet_num.end(); ++iter)
        outs << *iter << " ";
    outs << "\e[35mavg: \e[0m" << std::accumulate(std::begin(ps.packet_num), std::end(ps.packet_num), 0.0) / ps.packet_num.size();
    outs << "\e[35m max: \e[0m" << *std::max_element(ps.packet_num.begin(), ps.packet_num.end());
    outs << "\e[35m min: \e[0m" << *std::min_element(ps.packet_num.begin(), ps.packet_num.end()) << std::endl;

    outs << "\e[31mTotal Length(Byte):\e[0m\n";
    for (auto iter = ps.total_len.begin(); iter != ps.total_len.end(); ++iter)
        outs << *iter << " ";
    outs << "\e[35mavg: \e[0m" << std::accumulate(std::begin(ps.total_len), std::end(ps.total_len), 0.0) / ps.total_len.size();
    outs << "\e[35m max: \e[0m" << *std::max_element(ps.total_len.begin(), ps.total_len.end());
    outs << "\e[35m min: \e[0m" << *std::min_element(ps.total_len.begin(), ps.total_len.end()) << std::endl;

    outs << "\e[31mSkewness: \e[0m" << ps.skewness << std::endl << std::resetiosflags(std::ios::fixed) << std::setprecision(6);
    return outs;
}

}

#endif