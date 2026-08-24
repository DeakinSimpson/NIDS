#include <iostream>
#include <fstream> // for ifstream file reading
#include <string>
#include "pcap.hpp"
#include "packet.hpp"
#include "filehandler.hpp"
#include "printhelper.hpp"

namespace testVals
{
    const std::string tion { "NIDS/test/pcap/01-test.pcap" };
    const std::string fileLocation1 
        { "/home/deakin/Documents/projects/NIDS/test/pcap/01-test.pcap" };
    const std::string fileLocation2 
        { "/home/deakin/Documents/projects/NIDS/test/pcap/amd_test.pcapng" };
} 

int main()
{
    using print::operator<<;

    fh::FileHandler fileHandler { fh::FileHandler(testVals::fileLocation1) };
    std::ifstream& fs = fileHandler.getFileStream();
    if (!fs.good()) { return 1; }

    PcapFile pcapFile { PcapFile(fs) };
    std::cout << pcapFile.getPcapHeader().magicNumber << std::endl;

    for (int i { 0 }; i < 1; ++i)
    {
        packet::pcap_packet pkt { packet::pcap_packet(fs) };
        std::cout << pkt.getPacketRecordHead() << std::endl;
        std::cout << pkt.getPacket() << std::endl;
    }

    return 0;
}
