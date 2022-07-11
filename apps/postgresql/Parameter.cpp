#include "Parameter.h"
#include "pqtypes-int.h"

#include <jsonArg.h>

#include <netinet/in.h>

#ifndef ntohll
#define ntohll(b) __builtin_bswap64(b)
#endif

#ifndef htonll
#define htonll(b) __builtin_bswap64(b)
#endif

static inline bool      pq_get_bool(const char *value) { return (bool)*value; }
static inline int16_t   pg_get_int2(const char *value) { return (int16_t)ntohs(*(int16_t*)value); }
static inline int32_t   pq_get_int4(const char *value) { return (int32_t)ntohl(*(int32_t*)value); }
static inline int64_t   pq_get_int8(const char *value) { return ntohll(*(int64_t*)value); }
static inline const char*     pq_get_text(const char *value) { return value; }
static inline double    pq_get_float8(const char *value)
{
    union {
        uint64_t    bytes;
        double      value;
    } f;

    f.bytes = ntohll(*(uint64_t*)value);

    return f.value;
}

static inline float    pq_get_float4(const char *value)
{
    union {
        uint32_t    bytes;
        float      value;
    } f;

    f.bytes = ntohl(*(uint32_t*)value);

    return f.value;
}

QueryParam::QueryParam(bool val)
: oid(BOOLOID) {
    binvalue[0] = val;
}

QueryParam::QueryParam(int16_t val)
: oid(INT2OID) {
    *((int16_t*)binvalue) = ntohs(val);
}

QueryParam::QueryParam(int32_t val)
: oid(INT4OID) {
    *((int32_t*)binvalue) = ntohl(val);
}

QueryParam::QueryParam(int64_t val)
: oid(INT8OID) {
    *((int64_t*)binvalue) = ntohll(val);
}

QueryParam::QueryParam(uint16_t val)
: oid(INT4OID) {
    *((uint32_t*)binvalue) = ntohl((int32_t)val);
}

QueryParam::QueryParam(uint32_t val)
: oid(INT8OID) {
    *((uint64_t*)binvalue) = ntohll((int32_t)val);
}

QueryParam::QueryParam(float val)
: oid(FLOAT4OID) {
    union {
        uint32_t    bytes;
        float      value;
    } f;
    f.value = val;
    *((uint32_t*)binvalue) = ntohl(f.bytes);
}

QueryParam::QueryParam(double val)
: oid(FLOAT8OID) {
    union {
        uint64_t    bytes;
        double      value;
    } f;
    f.value = val;
    *((uint64_t*)binvalue) = ntohll(f.bytes);
}

QueryParam::QueryParam(const std::string& val)
: oid(TEXTOID), strvalue(val) {}

QueryParam::QueryParam(const char* val)
: oid(TEXTOID), strvalue(val) {}

QueryParam::QueryParam(const AmArg& val)
: oid(JSONOID){
    strvalue = arg2json(val);
}

unsigned int QueryParam::get_oid() {
    return oid;
}

const char * QueryParam::get_value()
{
    switch(oid) {
    case BOOLOID:
    case INT2OID:
    case INT4OID:
    case INT8OID:
    case FLOAT4OID:
    case FLOAT8OID:
        return binvalue;
    case TEXTOID:
    case JSONOID:
        return strvalue.c_str();
    }
    return "";
}

int QueryParam::get_length()
{
    switch(oid) {
    case BOOLOID:
        return sizeof(uint8_t);
    case INT2OID:
        return sizeof(uint16_t);
    case INT4OID:
        return sizeof(uint32_t);
    case INT8OID:
        return sizeof(uint64_t);
    case FLOAT4OID:
        return sizeof(float);
    case FLOAT8OID:
        return sizeof(double);
    case TEXTOID:
    case JSONOID:
        return strvalue.size();
    }
    return 0;
}

bool QueryParam::is_binary_format()
{
    switch(oid) {
    case BOOLOID:
    case INT2OID:
    case INT4OID:
    case INT8OID:
    case FLOAT4OID:
    case FLOAT8OID:
        return true;
    case TEXTOID:
    case JSONOID:
        return false;
    }
    return true;
}

AmArg get_result(unsigned int oid, bool is_binary, const char* value)
{
    switch(oid) {
    case VARCHAROID:
    case CHAROID:
    case TEXTOID:
    case INETOID:
    case CIDROID:
    case MACADDROID:
        return AmArg(value);
    case BOOLOID:
        if(is_binary) return AmArg((bool)value);
        else {
            if(value[0] == 't' ||
               value[0] == 'y' ||
               strcmp(value, "on") == 0 ||
               value[0] == '1')
                    return AmArg(true);
            else
                    return AmArg(false);
        }
    case NUMERICOID:
        return AmArg(atof(value));
    case INT2OID:
        if(is_binary) return AmArg(pg_get_int2(value));
        else return AmArg(atoi(value));
    case INT4OID:
        if(is_binary) return AmArg(pq_get_int4(value));
        else return AmArg(atol(value));
    case INT8OID:
        if(is_binary) return AmArg(pq_get_int8(value));
        else return AmArg(atoll(value));
    case FLOAT4OID:
        if(is_binary) return AmArg((double)pq_get_float4(value));
        else return AmArg(atof(value));
    case FLOAT8OID:
        if(is_binary) return AmArg(pq_get_float8(value));
        else return AmArg(atof(value));
    case JSONOID:
        AmArg ret;
        json2arg(value, ret);
        return ret;
    }
    return AmArg();
}

vector<QueryParam> getParams(const vector<AmArg>& params)
{
    vector<QueryParam> qparams;
    for(auto& param : params) {
        if(isArgInt(param))
            qparams.emplace_back(param.asInt());
        else if(isArgLongLong(param))
            qparams.emplace_back((int64_t)param.asLongLong());
        else if(isArgCStr(param))
            qparams.emplace_back(param.asCStr());
        else if(isArgDouble(param))
            qparams.emplace_back(param.asDouble());
        else if(isArgStruct(param) || isArgArray(param))
            qparams.emplace_back(param);
        else if(isArgBool(param))
            qparams.emplace_back(param.asBool());
    }
    return qparams;
}


