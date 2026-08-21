#include <iostream>
#include <fstream> // for ifstream file reading
#include <string>
#include "pcap.h"
#include "packet.h"
#include "filehandler.h"

#include <filesystem>

namespace testVals
{
    const std::string fileLocation { "NIDS/test/pcap/01-test.pcap" };
    const std::string fileLocation1 
        { "/home/deakin/Documents/projects/NIDS/test/pcap/01-test.pcap" };
} 

int main()
{
    fh::FileHandler fileHandler { fh::FileHandler(testVals::fileLocation1) };
    std::ifstream* fs = fileHandler.getFileStream();
    if (!fs->good()) { return 1; }

    PcapFile pcapFile { PcapFile(*fs) };

    packet::pkt_rec_head pkt_rec_head {};
    packet::eth_head eth_head {};

    packet::getPktRecHead(*fs, pkt_rec_head);
    fs->read(reinterpret_cast<char*>(&eth_head), sizeof(eth_head));

    std::cout << pkt_rec_head << std::endl;
    std::cout << pcapFile.getPcapHeader().network << std::endl;
    std::cout << eth_head << std::endl;
    std::cout << "IPV4 ?: " << packet::isIPV4(eth_head.type) << std::endl;

    return 0;
}
