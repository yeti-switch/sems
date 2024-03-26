#include "AmUtils.h"
#include "log.h"

#include <string>
#include <fstream>
#include <streambuf>
#include <iostream>
#include <cstdlib>

using namespace std;

int fixup_file(char *path) {
    ifstream f(path, ifstream::in);
    string s;

    if(!f.is_open()) {
        ERROR("failed to opend file: %s",path);
        return EXIT_FAILURE;
    }

    f.seekg(0, ios::end);
    s.reserve(f.tellg());
    f.seekg(0, ios::beg);

    s.assign(istreambuf_iterator<char>(f),
             istreambuf_iterator<char>());

    DBG("read %ld bytes from file %s",s.size(),path);
    DBG("original data:\n--\n%s\n--",s.data());

    if(fixup_utf8_inplace(s)) {
        DBG("fixed data:\n--\n%s\n--",s.data());
    } else {
        DBG("not modified");
    }

    return EXIT_SUCCESS;
}


int main(int argc, char *argv[])
{
    register_stderr_facility();
    set_stderr_log_level(L_DBG);

    if(argc > 1)
        return fixup_file(argv[1]);

    return EXIT_SUCCESS;
}

