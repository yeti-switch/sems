#ifndef PARAMETER_H
#define PARAMETER_H

#include <string>
using std::string;

#include <AmArg.h>

class QueryParam
{
    unsigned int oid;
    string strvalue;
    char binvalue[sizeof(double)];
public:
    QueryParam(bool val);
    QueryParam(int16_t val);
    QueryParam(int32_t val);
    QueryParam(int64_t val);
    QueryParam(uint16_t val);
    QueryParam(uint32_t val);
    QueryParam(float val);
    QueryParam(double val);
    QueryParam(const string& val);
    QueryParam(const char* val);
    QueryParam(const AmArg& val);
    int get_length();
    unsigned int get_oid();
    const char* get_value();
    bool is_binary_format();
};

AmArg get_result(unsigned int oid, bool is_binary, const char* value);
vector<QueryParam> getParams(const vector<AmArg>& params);

#endif/*PARAMETER_H*/
