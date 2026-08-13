#include <iostream>
#include <fstream> // for ifstream file reading
#include <string>
#include "pcap.h"

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

    return 0;
}
