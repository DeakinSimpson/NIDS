#pragma once

#include <fstream>
#include <string>

namespace fh
{
    class FileHandler
    {
        std::ifstream file_;

    public:
        FileHandler(const std::string& filename) 
            : file_(filename, std::ifstream::binary) { }

        bool isFSGood() { return file_.good(); }

        std::ifstream* getFileStream() { return &file_; }
    };
}

