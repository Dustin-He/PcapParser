#ifndef _VALUE_H
#define _VALUE_H

#include "PacketHeader.h"

namespace PcapValue {

enum ValueScheme {
    VAL_TIMESTAMP,
    VAL_LENGTH
};

class Value {
public:
    PacketHeader::TimeVal time_stamp;
    uint16_t length;
    uint8_t scheme;

    Value(uint8_t sc = 0) {
        scheme = sc;
    }

    std::string to_string() const;

};

std::string Value::to_string() const {
    std::string str;
    if (scheme & (1 << ValueScheme::VAL_TIMESTAMP)) {
        unsigned long long tm = ((unsigned long long)time_stamp.tv_sec << 32) + time_stamp.tv_usec;
        str += std::to_string(tm);
    }
    if (scheme & (1 << ValueScheme::VAL_LENGTH)) {
        if (str.empty())
            str += std::to_string((unsigned long)length);
        else
            str += std::string(" ") + std::to_string((unsigned long)length);
    }
    return str;
}

}

#endif