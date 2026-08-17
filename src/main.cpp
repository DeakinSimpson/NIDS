#include <iostream>
#include <fstream> // for ifstream file reading
#include <string>
#include "pcap.h"
#include "packet.h"

#include <filesystem>

namespace testVals
{
    const std::string fileLocation { "../test/pcap/01-test.pcap" };
} 

int main()
{
    // open pcap
    std::ifstream fs;
    fs.open(testVals::fileLocation, std::ifstream::binary);
    if (!fs.good()) { return 1; }

    PcapFile pcapFile { PcapFile(fs) };

    packet::pkt_rec_head pkt_rec_head {};
    packet::eth_head eth_head {};

    fs.read(reinterpret_cast<char*>(&pkt_rec_head), sizeof(pkt_rec_head));
    fs.read(reinterpret_cast<char*>(&eth_head), sizeof(eth_head));

    std::cout << pkt_rec_head << std::endl;
    std::cout << pcapFile.getPcapHeader().network << std::endl;
    std::cout << eth_head << std::endl;

    return 0;
}
