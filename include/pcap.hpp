#pragma once
#include <cstdint>
#include <fstream>

/* ensures there is no padding added to the struct, every header read is the 
   the exact correct bit lenth*/
#pragma pack(push, 1)
struct PcapHeader
{
  uint32_t magicNumber;
  uint16_t majorVersion;
  uint16_t minorVersion;
  uint32_t reserved1;
  uint32_t reserved2;
  uint32_t snapLen;
  uint32_t network;
};
#pragma pack(pop)

class PcapFile
{
public:
    PcapFile(std::ifstream& fs) { ReadPcapHeader(fs, this->header); }

    inline PcapHeader getPcapHeader() { return this->header; }
    bool isMicroSeconds() { return (this->header.magicNumber == 2712847316); }

    // checks if link type is ethernet (only one implemented)
    bool checkValidLinkType() { return (this->header.network == 1); }

private:
    PcapHeader header {};

    static void ReadPcapHeader(std::ifstream& fs, PcapHeader& header)
    {
        // reinterperet cast is a bit level cast
        fs.read(reinterpret_cast<char*>(&header), sizeof(header));
    }
};
