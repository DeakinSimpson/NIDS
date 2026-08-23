#pragma once

#include <cstdint>
#include <iostream>
#include <array>
#include <iomanip> // for std::setfill
#include <bitset>
#include <vector>
#include "filehandler.h"

#include <arpa/inet.h> // this is used to convert the integers

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

    struct eth_head
    {
        std::array<uint8_t, 6> destAddr {};
        std::array<uint8_t, 6> srcAddr {};
        std::array<uint8_t, 2> type {};
    };

    /*
     * https://en.wikipedia.org/wiki/IPv4#Packet_structure
     * -------------------------------------------------------------------------
     * version: should always equal 4 (IPv4)
     * -------------------------------------------------------------------------
     * Protocol numbers:
     * 
     * Protocol Number	Protocol Name	                        Abbreviation
     * 1	            Internet Control Message Protocol	    ICMP
     * 2	            Internet Group Management Protocol	    IGMP
     * 6	            Transmission Control Protocol	        TCP
     * 17	            User Datagram Protocol	                UDP
     * 41	            IPv6 encapsulation	                    ENCAP
     * 89	            Open Shortest Path First	            OSPF
     * 132	            Stream Control Transmission Protocol	SCTP
     */
    struct ip_pkt_header
    {
        uint16_t version_IHL_DSCP_ECN;
        uint16_t total_length;          // size of packet including header
        uint16_t identification;
        uint16_t flags_offset;
        uint16_t ttl_protocol;
        uint16_t header_checksum;
        uint32_t srcIP;
        uint32_t dstIP;
    };
    #pragma pack(pop)

    /*
    * how the masked bits function works:
    * v is the input bits
    * pos is where the bits start right to left
    * n is the number of bits we want masked
    * 
    * Example: (0101'0110'1010) | we want the middle 4 bits (left)
    * step 1: (v >> n) = (0101'0110'1010 >> 4) = 0000'0101'0110
    * step 2: (1u << n) = (0000'0000'0001 << 4) = 0000'0001'0000
    * step 3: (step2 - 1) = 0000'0001'0000 - 1 = 0000'0000'1111
    * step 4: step1-step3 = 0000'0101'0110 & 0000'0000'1111 = 0000'0000'0110
    */
    template <typename T>
    T getMaskedBits(uint16_t v, int pos, int n) {
        return static_cast<T>((ntohs(v) >> pos) & ((1u << n) - 1));
    }

    template <typename T>
    T getMaskedBits(uint32_t v, int pos, int n) {
        return static_cast<T>((ntohl(v) >> pos) & ((1u << n) - 1));
    }

    // casts filestream bytes into any type of output using reinterperate cast
    template <typename T>
    void fsCast(std::ifstream& fs, T& output) {
        fs.read(reinterpret_cast<char*>(&output), sizeof(T)); }

    class packet
    {
        eth_head                ethernetHeader_;
        ip_pkt_header           ipPacketHeader_;
        std::vector<uint8_t>    dataField_;

    public:
        // getters for private fields
        const eth_head& getEthernetHeader() const { return ethernetHeader_; }
        const ip_pkt_header& getIpPacketHeader() const { return ipPacketHeader_; }
        const std::vector<uint8_t>& getDataField() const { return dataField_; }

        packet(std::ifstream& fs)
            : ethernetHeader_ {  }
            , ipPacketHeader_ {  }
            , dataField_      {  }
        {
            fsCast(fs, ethernetHeader_);
            fsCast(fs, ipPacketHeader_);
            ingestDataField(fs, dataField_, getDataFieldLength());
        }

        void ingestDataField(
              std::ifstream& fs
            , std::vector<uint8_t>& dataField, const int numBytes)
        {
            for (int i { 0 }; i < numBytes; ++i)
            {
                uint8_t byte {};
                fsCast(fs, byte);
                dataField.push_back(byte);
            }
        }

        int getDataFieldLength() const { return getTotalLength() - (getIHL() * 4); }

        // should be 4 for IPv4
        int getVersion() const {
            return getMaskedBits<int>(ipPacketHeader_.version_IHL_DSCP_ECN, 12, 4); }

        int getIHL() const {
            return getMaskedBits<int>(ipPacketHeader_.version_IHL_DSCP_ECN, 8, 4); }

        int getTTL() const {
            return getMaskedBits<int>(ipPacketHeader_.ttl_protocol, 8, 8); }

        int getTotalLength() const {
            return static_cast<int>(ntohs(ipPacketHeader_.total_length)); }

        int getProtocol() const {
            return getMaskedBits<int>(ipPacketHeader_.ttl_protocol, 0, 8); }

        int getOptionsLength() const {
            if (getIHL() <= 5) { return 0; }
            return getIHL() - 5; }       
            
    };

    class pcap_packet
    {
        pkt_rec_head packetRecordHead_;
        packet packet_;

    public:
        pcap_packet(std::ifstream& fs)
            : packetRecordHead_(readPktRecHead(fs))
            , packet_(fs)
        {  }

        const pkt_rec_head& getPacketRecordHead() { return packetRecordHead_; }
        const packet& getPacket() { return packet_; }

        pkt_rec_head readPktRecHead(std::ifstream& fs)
        {
            pkt_rec_head head {};
            fsCast(fs, head);
            return head;
        }
    };
}
