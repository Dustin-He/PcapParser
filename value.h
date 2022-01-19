#ifndef _VALUE_H
#define _VALUE_H

#include "PacketHeader.h"

class Value {
public:
    TimeVal time_stamp;
    uint16_t length;
    uint8_t scheme;

    Value(uint8_t sc = 0) {
        scheme = sc;
    }
};

#endif