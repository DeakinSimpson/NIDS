#pragma once

#include <iostream>
#include <iomanip>
#include "packet.hpp"

namespace print
{
    inline std::ostream& operator<<(std::ostream& os
        , const packet::pkt_rec_head& pkt_rec_head)
    {
        os << "--- Packet Record Header ---" << std::endl;
        os << "Timestamp (Seconds): " << pkt_rec_head.tsSeconds << '\n';
        os << "Timestamp (Microseconds or nanoseconds): ";
        os << pkt_rec_head.tsMsNs << '\n';
        os << "Captured Packet Length: " << pkt_rec_head.capPktLength << '\n';
        os << "Original Packet Length (32 bits): ";
        os << pkt_rec_head.pktLength << '\n';

        return os;
    }

    inline std::ostream& operator<<(std::ostream& os
        , const packet::eth_head& eth_head)
    {
        os << "--- Ethernet Header Info ---" << std::endl;
        // print dest mac           set to hex
        os << "Dest MAC: " << std::hex << std::setfill('0');
        for (uint64_t i { 0 }; i < 6; ++i)
        {
            os << static_cast<unsigned int>(eth_head.destAddr[i]);

            if (i != 5) { os << ":"; }
        }

        // print src mac
        os << "\nSource MAC: ";
        for (uint64_t i { 0 }; i < 6; ++i)
        {
            os << static_cast<unsigned int>(eth_head.srcAddr[i]);

            if (i != 5) { os << ":"; }
        }

        // print type
        os  << "\nType: 0x";
        os  << std::setw(2) << static_cast<unsigned int>(eth_head.type[0]) 
            << std::setw(2) << static_cast<unsigned int>(eth_head.type[1])
            << std::endl;
        // set back to decimal
        os << std::dec;

        return os;
    }

    inline void printIP(const uint32_t ip_net)
    {
        // NOTE: super innefficient, only use for testing
        // convert in to little endian or big endian based on system
        uint32_t ip_host { ntohl(ip_net) };

        // cast the 32 uint to a octet array
        std::array<uint8_t, 4> octets {
            static_cast<uint8_t>((ip_host >> 24) & 0xFF), // 0xFF = 1111'1111
            static_cast<uint8_t>((ip_host >> 16) & 0xFF),
            static_cast<uint8_t>((ip_host >> 8 ) & 0xFF),
            static_cast<uint8_t>((ip_host)       & 0xFF)
        };
        
        // cast each array member to an unsigned int to print
        std::cout  << static_cast<unsigned int>(octets[0]) 
            << "." << static_cast<unsigned int>(octets[1]) 
            << "." << static_cast<unsigned int>(octets[2]) 
            << "." << static_cast<unsigned int>(octets[3]) 
            << std::endl;
    }

    inline std::ostream& operator<<(std::ostream& os, const packet::packet& pkt)
    {
        os << pkt.getEthernetHeader() << '\n';

        // packet details
        os << "--- Packet Info ---" << '\n';
        os << "IP version:                      " 
            << pkt.getVersion() << '\n';
        os << "IHL:                             " 
            << pkt.getIHL() << '\n';
        os << "Total Length (including header): " 
            << pkt.getTotalLength() << '\n';
        os << "TTL:                             " 
            << pkt.getTTL() << '\n';
        os << "Protocol:                        " 
            << pkt.getProtocol() << '\n';
        os << "src IP:                          ";
            printIP(pkt.getIpPacketHeader().srcIP);
        os << "dst IP:                          ";
            printIP(pkt.getIpPacketHeader().dstIP);

        return os;
    }

    
}
