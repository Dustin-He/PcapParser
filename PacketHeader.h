#ifndef _PACKET_HEADER_H
#define _PACKET_HEADER_H

namespace PacketHeader {

#pragma pack(1)

// pcap文件头结构体
struct PcapFileHeader {
    uint32_t magic;         // 0xa1b2c3d4
    uint16_t version_major; // magjor Version 2
    uint16_t version_minor; // magjor Version 4
    int32_t thiszone;       // gmt to local correction
    uint32_t sigfigs;       // accuracy of timestamps
    uint32_t snaplen;       // max length saved portion of each pkt
    uint32_t linktype;      // data link type (LINKTYPE_*)
};

//时间戳
struct TimeVal {
    uint32_t tv_sec;        // seconds 含义同 time_t 对象的值
    uint32_t tv_usec;       // microseconds
};

// pcap数据包头结构体
struct PcapPacketHeader {
    TimeVal time_stamp;     // time stamp
    uint32_t caplen;        // 当前数据区的长度，即抓取到的数据帧长度
    uint32_t len;           // 离线数据长度：网络中实际数据帧的长度，一般不大于caplen，多数情况下和Caplen数值相等
    void reverseEndian();
};

//数据帧头
struct FrameHeader {        // Pcap捕获的数据帧头
    uint8_t dst_mac[6];     // 目的MAC地址
    uint8_t src_mac[6];     // 源MAC地址
    uint16_t frame_type;    // 帧类型
};

// IP数据报头(ipv4)
struct IPHeader {
    uint8_t ver_hlen;       // 版本+报头长度
    uint8_t tos;            // 服务类型
    uint16_t total_len;     // 总长度
    uint16_t id;            // 标识
    uint16_t flag_segment;  // 标志+片偏移
    uint8_t ttl;            // 生存周期
    uint8_t protocol;       // 协议类型
    uint16_t checksum;      // 头部校验和
    uint32_t src_ip;        // 源IP地址
    uint32_t dst_ip;        // 目的IP地址
};

// TCP数据报头
struct TCPHeader {
    uint16_t src_port;      // 源端口
    uint16_t dst_port;      // 目的端口
    uint32_t seq_no;        // 序号
    uint32_t ack_no;        // 确认号
    uint8_t offset;         // 数据的偏移(4 bit) + 保留(4 bit)
    uint8_t flags;          // 标识TCP不同的控制消息
    uint16_t window;        // 窗口大小
    uint16_t checksum;      // 校验和
    uint16_t urgent_ptr;    // 紧急指针
};

// UDP数据
struct UDPHeader {
    uint16_t src_port;      // 源端口号16bit
    uint16_t dst_port;      // 目的端口号16bit
    uint16_t len;           // 数据包长度16bit
    uint16_t checksum;      // 校验和16bit
};

inline uint16_t reverseEndianS(uint16_t x) {
    return ((x >> 8) ^ (x << 8));
}

inline uint32_t reverseEndianL(uint32_t x) {
    return reverseEndianS(x >> 16) ^ (reverseEndianS(x & 0x0000ffff) << 16);
}

inline uint64_t reverseEndianD(uint64_t x) {
    return reverseEndianL(x >> 32) ^ ((uint64_t)reverseEndianL(x & 0x00000000ffffffff) << 32);
}

void PcapPacketHeader::reverseEndian() {
    time_stamp.tv_sec = reverseEndianL(time_stamp.tv_sec);
    time_stamp.tv_usec = reverseEndianL(time_stamp.tv_usec);
    len = reverseEndianL(len);
    caplen = reverseEndianL(caplen);
}

#pragma pack()

}

#endif