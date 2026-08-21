#pragma once

#include <cstdint>
#include <iostream>
#include <array>
#include <iomanip> // for std::setfill
#include "filehandler.h"

namespace packet
{
    #pragma pack(push, 1)
    /*
    * --------------------------------------------------------------------------
    * | https://www.endace.com/learn/what-is-a-pcap-file                       |
    * --------------------------------------------------------------------------
    * Timestamp (Seconds): the number of seconds that have elapsed since 
    * 1970-01-01 00:00:00 UTC
    * --------------------------------------------------------------------------
    * Timestamp (Microseconds or nanoseconds): the number of microseconds or 
    * nanoseconds that have elapsed since the last full second.
    * --------------------------------------------------------------------------
    * Captured Packet Length: the number of octets captured from the packet, if 
    * packets are truncated this value is the length of the truncated packet.
    * --------------------------------------------------------------------------
    * Original Packet Length (32 bits): the actual length of the packet when it 
    * was transmitted on the network. 
    * --------------------------------------------------------------------------
    */
    struct pkt_rec_head
    {
        uint32_t tsSeconds;
        uint32_t tsMsNs;
        uint32_t capPktLength;
        uint32_t pktLength;
    };

    /*
     * Preamble not implemented as only ethernet packets will be implemented
     */
    // struct preamble_head
    // {
    //     std::array<uint8_t, 7> preamble {};
    //     uint8_t SOF {};
    // };

    struct eth_head
    {
        std::array<uint8_t, 6> destAddr {};
        std::array<uint8_t, 6> srcAddr {};
        std::array<uint8_t, 2> type {};
    };

    struct ip_pkt
    {

    };

    struct pkt_rec
    {
        pkt_rec_head header;
        eth_head ethernetHeader;
        ip_pkt ipPacket;
        uint32_t ethFrameChecksum;
    };
    #pragma pack(pop)

    std::ostream& operator<<(std::ostream& os, const pkt_rec_head& pkt_rec_head)
    {
        os << "Timestamp (Seconds): " << pkt_rec_head.tsSeconds << '\n';
        os << "Timestamp (Microseconds or nanoseconds): ";
        os << pkt_rec_head.tsMsNs << '\n';
        os << "Captured Packet Length: " << pkt_rec_head.capPktLength << '\n';
        os << "Original Packet Length (32 bits): ";
        os << pkt_rec_head.pktLength << '\n';

        return os;
    }

    std::ostream& operator<<(std::ostream& os, const eth_head& eth_head)
    {
        // print dest mac           set to hex
        std::cout << "Dest MAC: " << std::hex << std::setfill('0');
        for (uint64_t i { 0 }; i < 6; ++i)
        {
            std::cout << static_cast<unsigned int>(eth_head.destAddr[i]);

            if (i != 5) { std::cout << ":"; }
        }

        // print src mac
        std::cout << "\nSource MAC: ";
        for (uint64_t i { 0 }; i < 6; ++i)
        {
            std::cout << static_cast<unsigned int>(eth_head.srcAddr[i]);

            if (i != 5) { std::cout << ":"; }
        }

        // print type
        std::cout << "\nType: 0x";
        std::cout << std::setw(2) << static_cast<unsigned int>(eth_head.type[0]) 
                  << std::setw(2) << static_cast<unsigned int>(eth_head.type[1])
                  << std::endl;
        // set back to decimal
        std::cout << std::dec;

        return os;
    }

    // check if the type is ipv4 (0x0800 == ipv4)
    bool isIPV4(const std::array<uint8_t, 2>& type) {
        if (    static_cast<unsigned int>(type[0]) == 8 
            &&  static_cast<unsigned int>(type[1]) == 0) 
        { return true; }

        return false;
    }

    void getPktRecHead(std::ifstream& fs, pkt_rec_head& output)
    {
        fs.read(reinterpret_cast<char*>(&output), sizeof(pkt_rec_head));
    }
}
