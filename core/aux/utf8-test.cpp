#include "AmUtils.h"
#include "log.h"

#include <string>
#include <fstream>
#include <streambuf>
#include <iostream>
#include <cstdlib>

using namespace std;

vector<string> samples = {
    "<>",
    "\xF5>",
    "<\xF5>",
    "<\xF5\xF5>",
    "<\xC3\xA6>",
    "<\xC3\x70>",
    "<\xE0\xA0\x70>",
    "\xE0\xA0\x70>",
    "<\xF0\x90\x80\x80>",
    "<\xF0\x89\x80\x80>",
    "<\xF0\x90\x79\x80>",
    "<\xF0\x90\x80\x79>",
    "<\xE4>",
    "<\xE4|\xE4>",
    "\xF0",
    "<\xF0",
    "<\xF0\x90",
    "<\xF0\x90\x80",
    "\xF0\x90\x80"
};

void test_validation()
{
    cout << std::hex;
    for(auto &s: samples) {
        for(auto &c: s)
            cout << (((unsigned int)c)&0xff) << " ";
        cout << "| " << s << " | " << is_valid_utf8(s) << endl << endl;
    }
}

void test_fixup()
{
    auto processed_samples = samples;
    vector<bool> fixed;

    for(size_t i = 0; i<samples.size();i++)
    {
        fixed.push_back(fixup_utf8_inplace(processed_samples[i]));
        for(auto &c: samples[i])
            cout << (((unsigned int)c)&0xff) << " ";
        cout << "| " << samples[i] << " | " << processed_samples[i] << " | " <<
             fixed[i] <<
             endl << endl;
    }
}

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

    test_validation();

    test_fixup();

    return EXIT_SUCCESS;
}

