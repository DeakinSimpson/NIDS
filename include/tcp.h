#pragma once

#include <cstdint>
#include <vector>

namespace packet
{
    struct tcp_header
    {
        uint16_t src_port;
        uint16_t dst_port;
        uint32_t seq_num;
        uint32_t ack_num;
        uint16_t drf; // data offset, reserved, flags
        uint16_t window;
        uint16_t checksum;
        uint16_t urgent_pointer;
    };

    class tcp
    {
        tcp_header tcpHeader_;
        std::vector<uint32_t> options_;
        std::vector<uint8_t> data_;

    public:
        
    };
}
