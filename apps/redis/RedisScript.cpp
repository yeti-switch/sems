#include "RedisScript.h"
#include <fstream>

int Utils::read_file_data(const string &path, string &data)
{
    try {
        std::ifstream f(path);
        if(!f) {
            ERROR("failed to open: %s", path.c_str());
            return -1;
        }

        data = string((std::istreambuf_iterator<char>(f)),
                      (std::istreambuf_iterator<char>()));
    } catch(...) {
        ERROR("failed to load %s", path.c_str());
        return -1;
    }
    return 0;
}
