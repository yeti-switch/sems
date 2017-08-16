#include "AmUtils.h"
#include "log.h"

#include <fstream>
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

int main(int argc, char *argv[])
{
    register_stderr_facility();
    set_stderr_log_level(L_DBG);

    test_validation();

    test_fixup();

    return EXIT_SUCCESS;
}

