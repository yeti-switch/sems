/*
 * Copyright (C) 2002-2003 Fhg Fokus
 *
 * This file is part of SEMS, a free SIP media server.
 *
 * SEMS is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version. This program is released under
 * the GPL with the additional exemption that compiling, linking,
 * and/or using OpenSSL is allowed.
 *
 * For a license to use the SEMS software under conditions
 * other than those described here, or to purchase support for this
 * software, please contact iptel.org by e-mail at the following addresses:
 *    info@iptel.org
 *
 * SEMS is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License 
 * along with this program; if not, write to the Free Software 
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include "AmArg.h"
#include "log.h"
#include "AmUtils.h"
#include <limits>

#ifdef USE_AMARG_STATISTICS
#include "AmStatistics.h"
    AtomicCounter& amargsize = stat_group(Gauge, "core", "amarg_memory").addAtomicCounter();

    #define INC_AMARGSIZE(s) amargsize.inc(s)
    #define DEC_AMARGSIZE(s) amargsize.dec(s)

    #define INC_AMARGSTRUCT_SIZE(v_struct) \
        for(auto& it : *v_struct) { \
            INC_AMARGSIZE(strlen(it.first.c_str())); \
        }

    #define DEC_AMARGSTRUCT_SIZE(v_struct) \
        for(auto& it : *v_struct) { \
            DEC_AMARGSIZE(strlen(it.first.c_str())); \
        }

    #define INC_IF_AMARGSIZE(key) \
        if(v_struct->find(key) == v_struct->end())\
            INC_AMARGSIZE(strlen(key));

    #define DEC_IF_AMARGSIZE(name) \
        if(v_struct->find(name) != v_struct->end())\
            DEC_AMARGSIZE(strlen(name));
#else 
    #define INC_AMARGSIZE(s)
    #define DEC_AMARGSIZE(s)
    #define INC_AMARGSTRUCT_SIZE(v_struct)
    #define DEC_AMARGSTRUCT_SIZE(v_struct)
    #define INC_IF_AMARGSIZE(key)
    #define DEC_IF_AMARGSIZE(key)
#endif/*USE_AMARG_STATISTICS*/


//ArgBlob

ArgBlob::ArgBlob()
  : data(nullptr),
    len(0)
{
    INC_AMARGSIZE(sizeof(*this));
}

ArgBlob::ArgBlob(const ArgBlob& a)
{
    len = a.len;
    data = malloc(len);
    if(data)
        memcpy(data, a.data, len);
    INC_AMARGSIZE(sizeof(*this) + len);
}

ArgBlob::ArgBlob(const void* _data, int _len)
{
    len = _len;
    data = malloc(len);
    if(data)
        memcpy(data, _data, len);
    INC_AMARGSIZE(sizeof(*this) + _len);
}

ArgBlob::~ArgBlob()
{
    if(data) free(data);
    DEC_AMARGSIZE(sizeof(*this) + len);
}

//AmArg::ValueRef

AmArg::ValueRef::ValueRef(AmObject *arg)
  : arg_ptr(arg)
{ }

void AmArg::ValueRef::on_destroy()
{
    delete arg_ptr;
}

AmArg &AmArg::ValueRef::arg() const {
    DBG("arg(): arg_ptr: %p, arg_ptr, amarg: %p",
        arg_ptr, dynamic_cast<AmArg *>(arg_ptr));
    return *dynamic_cast<AmArg *>(arg_ptr);
}

//AmArg

void AmArg::invalidate()
{
    if(type == CStr) {
        DEC_AMARGSIZE(strlen(v_cstr));
        free((void*)v_cstr); 
    }
    else if(type == Array) { delete v_array; }
    else if(type == Struct) {
        DEC_AMARGSTRUCT_SIZE(v_struct);
        delete v_struct; 
    }
    else if(type == Blob) { delete v_blob; }
    else if(type == Reference) { dec_ref(v_ref); }
    type = Undef;
}

AmArg::AmArg()
  : type(Undef)
{
    INC_AMARGSIZE(sizeof(*this));
}

AmArg::AmArg(const AmArg& v)
{
    type = Undef;
    *this = v;
    INC_AMARGSIZE(sizeof(*this));
}

AmArg::AmArg(const int& v)
  : type(Int),
    v_int(v)
{
    INC_AMARGSIZE(sizeof(*this));
}

AmArg::AmArg(const long int& v)
  : type(Int),
    v_int(v)
{
    INC_AMARGSIZE(sizeof(*this));
}

AmArg::AmArg(const unsigned int& v)
  : type(LongLong),
    v_long(v)
{
    INC_AMARGSIZE(sizeof(*this));
}

AmArg::AmArg(const long unsigned int& v)
  : type(LongLong),
    v_long(v)
{
    INC_AMARGSIZE(sizeof(*this));
}

AmArg::AmArg(const long long int& v)
  : type(LongLong),
    v_long(v)
{
    INC_AMARGSIZE(sizeof(*this));
}

AmArg::AmArg(const bool& v)
  : type(Bool),
    v_bool(v)
{
    INC_AMARGSIZE(sizeof(*this));
}

AmArg::AmArg(const double& v)
  : type(Double),
    v_double(v)
{
    INC_AMARGSIZE(sizeof(*this));
}

AmArg::AmArg(const char* v)
  : type(CStr)
{
    INC_AMARGSIZE(sizeof(*this) + strlen(v));
    v_cstr = strdup(v);
}

AmArg::AmArg(const string &v)
  : type(CStr)
{
    INC_AMARGSIZE(sizeof(*this) + strlen(v.c_str()));
    v_cstr = strdup(v.c_str());
}

AmArg::AmArg(const ArgBlob v)
  : type(Blob)
{
    INC_AMARGSIZE(sizeof(*this));
    v_blob = new ArgBlob(v);
}

AmArg::AmArg(AmObject* v, bool reference)
{
    if(reference) {
        type = Reference;
        v_ref = new ValueRef(v);
        inc_ref(v_ref);
    } else {
        type = AObject;
        v_obj = v;
    }
    INC_AMARGSIZE(sizeof(*this));
}

AmArg::AmArg(AmDynInvoke* v) 
  : type(ADynInv),
    v_inv(v)
{
    INC_AMARGSIZE(sizeof(*this));
}

AmArg::AmArg(std::map<std::string, std::string>& v)
  : type(Undef)
{
    assertStruct();
    INC_AMARGSIZE(sizeof(*this));
    for(std::map<std::string, std::string>::iterator it =
        v.begin();it!= v.end();it++)
    {
        INC_AMARGSIZE(strlen(it->first.c_str()));
        (*v_struct)[it->first] = AmArg(it->second.c_str());
    }
}

AmArg::AmArg(std::map<std::string, AmArg>& v)
  : type(Undef)
{
    assertStruct();
    INC_AMARGSIZE(sizeof(*this)); 
    for(std::map<std::string, AmArg>::iterator it =
        v.begin();it!= v.end();it++)
    {
        INC_AMARGSIZE(strlen(it->first.c_str()));
        (*v_struct)[it->first] = it->second;
    }
}

AmArg::AmArg(std::vector<std::string>& v)
  : type(Array)
{
    assertArray();
    INC_AMARGSIZE(sizeof(*this));
    for(std::vector<std::string>::iterator it =
        v.begin(); it != v.end(); it++)
    {
        push(AmArg(it->c_str()));
    }
}

AmArg::AmArg(const std::vector<int>& v )
  : type(Array)
{
    assertArray(0);
    INC_AMARGSIZE(sizeof(*this));
    for(std::vector<int>::const_iterator it =
        v.begin(); it != v.end(); it++)
    {
        push(AmArg(*it));
    }
}

AmArg::AmArg(const std::vector<double>& v)
  : type(Array)
{
    assertArray(0);
    INC_AMARGSIZE(sizeof(*this));
    for(std::vector<double>::const_iterator it =
        v.begin(); it != v.end(); it++)
    {
        push(AmArg(*it));
    }
}

AmArg& AmArg::operator=(const AmArg& v)
{
    if (this != &v) {
        invalidate();

        type = v.type;
        switch(type) {
        case Int:    { v_int = v.v_int; } break;
        case LongLong: { v_long = v.v_long; } break;
        case Bool:   { v_bool = v.v_bool; } break;
        case Double: { v_double = v.v_double; } break;
        case CStr:   {
            v_cstr = strdup(v.v_cstr);
            INC_AMARGSIZE(strlen(v.v_cstr));
        } break;
        case AObject:{ v_obj = v.v_obj; } break;
        case ADynInv:{ v_inv = v.v_inv; } break;
        case Array:  { v_array = new ValueArray(*v.v_array); } break;
        case Struct: {
            INC_AMARGSTRUCT_SIZE(v.v_struct);
            v_struct = new ValueStruct(*v.v_struct);
        } break;
        case Blob:   { v_blob = new ArgBlob(*v.v_blob); } break;
        case Reference:
            v_ref = v.v_ref;
            inc_ref(v_ref);
            break;
        case Undef: break;
        default: assert(0);
        }
    }
    return *this;
}

AmArg::~AmArg() {
    invalidate();
    DEC_AMARGSIZE(sizeof(*this));
}

void AmArg::clear()
{
    invalidate();
}

void AmArg::assertArray()
{
    if(Array == type)
        return;
    if(Undef == type) {
        type = Array;
        v_array = new ValueArray();
        return;
    }
    throw TypeMismatchException();
}


void AmArg::assertArray(size_t s)
{
    if(Undef == type) {
        type = Array;
        v_array = new ValueArray();
    } else if(Array != type) {
        throw TypeMismatchException();
    }
    if(v_array->size() < s)
        v_array->resize(s);
}

void AmArg::assertArray() const
{
    if(Array != type)
        throw TypeMismatchException();
}

void AmArg::assertStruct()
{
    if(Struct == type)
        return;
    if(Undef == type) {
        type = Struct;
        v_struct = new ValueStruct();
        return;
    }
    throw TypeMismatchException();
}

void AmArg::assertStruct() const {
  if (Struct != type)
    throw TypeMismatchException();
}

void AmArg::assertType(Type expected_type) const {
    if(type != expected_type) {
        ERROR("type mismatch: expected: %d; received: %d.",
              expected_type, type);
        throw TypeMismatchException();
    }
}

bool AmArg::isNumber() const
{
    switch(type) {
    case Int:
    case LongLong:
    case Double:
        return true;
    default: break;
    }
    return false;
}

void AmArg::setBorrowedPointer(AmObject* v)
{
    invalidate();
    type = AObject;
    v_obj = v;
}

AmArg &AmArg::getReferencedValue() const
{
    if(Reference != type)
        throw TypeMismatchException();
    return v_ref->arg();
}

size_t AmArg::getAllocatedSize()
{
    size_t size = sizeof(*this);
    switch(type) {
    case CStr:
        size += strlen(v_cstr);
        break;
    case Blob:
        size += v_blob->len + sizeof(*v_blob);
        break;
    case Array:
        for(size_t i = 0; i < this->size(); i ++)
            size += (*v_array)[i].getAllocatedSize();
        break;
    case Struct:
        for (auto& it : *v_struct) {
            size += it.first.size();
            size += it.second.getAllocatedSize();
        }
        break;
    case Reference:
        size+=v_ref->arg().getAllocatedSize();
        break;
    default: break;
    }
    return size;
}

std::string AmArg::print() const
{
    string s;
    switch(type) {
    case Undef:
        return "";
    case Int:
        return v_int < 0 ?
            "-"+long2str(abs(v_int)) :
            long2str(v_int);
    case LongLong:
        return longlong2str(v_long);
    case Bool:
        return v_bool ? "true" : "false";
    case Double:
        if(v_double == std::numeric_limits<double>::infinity())
            return "\"inf\"";
        return double2str(v_double);
    case CStr:
        return "'" + string(v_cstr) + "'";
    case AObject:
        return "<Object>";
    case ADynInv:
        return "<DynInv>";
    case Blob:
        s = "<Blob of size:" + int2str(v_blob->len) + ">";
    case Array:
        s = "[";
        for(size_t i = 0; i < size(); i ++)
            s += print((*v_array)[i]) + ", ";
        if(1 < s.size())
            s.resize(s.size() - 2); // strip last ", "
        s += "]";
        return s;
    case Struct:
        s = "{";
        for(AmArg::ValueStruct::const_iterator it = v_struct->begin();
            it != v_struct->end(); it ++)
        {
            s += "'"+it->first + "': ";
            s += print(it->second);
            s += ", ";
        }
        if(1 < s.size())
            s.resize(s.size() - 2); // strip last ", "
        s += "}";
        return s;
    case Reference:
        s = print(v_ref->arg());
        return s;
    default: break;
    }
    return "<UNKONWN TYPE>";
}

const char* AmArg::t2str(int type)
{
    switch (type) {
    case AmArg::Undef:   return "Undef";
    case AmArg::Int:     return "Int";
    case AmArg::LongLong: return "LongLong";
    case AmArg::Bool:    return "Bool";
    case AmArg::Double:  return "Double";
    case AmArg::CStr:    return "CStr";
    case AmArg::AObject: return "AObject";
    case AmArg::ADynInv: return "ADynInv";
    case AmArg::Blob:    return "Blob";
    case AmArg::Array:   return "Array";
    case AmArg::Struct:  return "Struct";
    default: return "unknown";
    }
}

string AmArg::print(const AmArg &a)
{
    return a.print();
}

size_t AmArg::size() const
{
    if(Array == type)
        return v_array->size(); 

    if(Struct == type)
        return v_struct->size(); 

    throw TypeMismatchException();
}

void AmArg::push(const AmArg& a)
{
    assertArray();
    v_array->push_back(a);
}

void AmArg::push(const string &key, const AmArg &val)
{
    assertStruct();
    (*v_struct)[key] = val;
    INC_AMARGSIZE(strlen(key.c_str()));
}

void AmArg::pop(AmArg &a)
{
    assertArray();
    if(!size()) {
        if(a.getType() == AmArg::Undef)
            return;
        a = AmArg();
        return;
    }
    a = v_array->front();
    v_array->erase(v_array->begin());
}

void AmArg::pop_back(AmArg &a)
{
    assertArray();
    if(!size()) {
        if(a.getType() == AmArg::Undef)
            return;
        a = AmArg();
        return;
    }
    a = v_array->back();
    v_array->erase(v_array->end());
}

void AmArg::pop_back()
{
    assertArray();
    if(!size())
        return;
    v_array->erase(v_array->end());
}

void AmArg::erase(size_t idx)
{
    assertArray();
    if(idx < 0 || idx >= v_array->size())
        throw OutOfBoundsException();
    v_array->erase(v_array->begin()+idx);
}

void AmArg::concat(const AmArg& a)
{
    assertArray();
    if(a.getType() == Array) {
        for(size_t i=0;i<a.size();i++)
            v_array->push_back(a[i]);
    } else {
        v_array->push_back(a);
    }
}

AmArg& AmArg::back()
{
    assertArray();
    if(!v_array->size())
        throw OutOfBoundsException();

    return (*v_array)[v_array->size()-1];
}

AmArg& AmArg::back() const
{
    assertArray();
    if(!v_array->size())
        throw OutOfBoundsException();

    return (*v_array)[v_array->size()-1];
}

AmArg& AmArg::get(size_t idx)
{
    assertArray();
    if (idx >= v_array->size())
        throw OutOfBoundsException();

    return (*v_array)[idx];
}

AmArg& AmArg::get(size_t idx) const
{
    assertArray();
    if(idx >= v_array->size())
        throw OutOfBoundsException();

    return (*v_array)[idx];
}

AmArg& AmArg::operator[](size_t idx)
{
    assertArray(idx+1); 
    return (*v_array)[idx];
}

AmArg& AmArg::operator[](int idx)
{
    if(idx<0)
        throw OutOfBoundsException();
    assertArray(idx+1); 
    return (*v_array)[idx];
}

AmArg& AmArg::operator[](unsigned int idx)
{
    assertArray(idx+1); 
    return (*v_array)[idx];
}

AmArg& AmArg::operator[](size_t idx) const
{
    assertArray();
    if(idx >= v_array->size())
        throw OutOfBoundsException();

    return (*v_array)[idx];
}

AmArg& AmArg::operator[](int idx) const
{
    if(idx<0)
        throw OutOfBoundsException();
    assertArray();
    if((size_t)idx >= v_array->size())
        throw OutOfBoundsException();

    return (*v_array)[idx];
}

AmArg& AmArg::operator[](unsigned int idx) const
{
    assertArray();
    if(idx >= v_array->size())
        throw OutOfBoundsException();

    return (*v_array)[idx];
}

AmArg& AmArg::operator[](std::string key)
{
    assertStruct();
    INC_IF_AMARGSIZE(key.c_str());

    return (*v_struct)[key];
}

AmArg& AmArg::operator[](std::string key) const
{
    assertStruct();
    INC_IF_AMARGSIZE(key.c_str());

    return (*v_struct)[key];
}

AmArg& AmArg::operator[](const char* key)
{
    assertStruct();
    INC_IF_AMARGSIZE(key);

    return (*v_struct)[key];
}

AmArg& AmArg::operator[](const char* key) const
{
    assertStruct();
    INC_IF_AMARGSIZE(key);

    return (*v_struct)[key];
}

bool AmArg::hasMember(const char* name) const
{
    return type == Struct &&
           v_struct->find(name) != v_struct->end();
}

bool AmArg::hasMember(const string& name) const
{
    return type == Struct &&
           v_struct->find(name) != v_struct->end();
}

std::vector<std::string> AmArg::enumerateKeys() const
{
    assertStruct();
    std::vector<std::string> res;
    for (ValueStruct::iterator it = 
        v_struct->begin(); it != v_struct->end(); it++)
    {
        res.push_back(it->first);
    }
    return res;
}

AmArg::ValueStruct::const_iterator AmArg::begin() const
{
    assertStruct();
    return v_struct->begin();
}

AmArg::ValueStruct::const_iterator AmArg::end() const
{
    assertStruct();
    return v_struct->end();
}

void AmArg::erase(const char* name)
{
    assertStruct();
    DEC_IF_AMARGSIZE(name);
    v_struct->erase(name);
}

void AmArg::erase(const std::string& name)
{
    assertStruct();
    DEC_IF_AMARGSIZE(name.c_str());
    v_struct->erase(name);
}

void AmArg::assertArrayFmt(const char* format) const
{
    size_t fmt_len = strlen(format);
    string got;
    try {
        for(size_t i=0;i<fmt_len;i++) {
            switch (format[i]) {
            case 'i': get(i).assertType(Int); got+='i';  break;
            case 'l': get(i).assertType(LongLong); got+='l';  break;
            case 't': get(i).assertType(Bool); got+='t';  break;
            case 'f': get(i).assertType(Double); got+='f'; break;
            case 's': get(i).assertType(CStr); got+='s'; break;
            case 'o': get(i).assertType(AObject); got+='o'; break;
            case 'd': get(i).assertType(ADynInv); got+='d'; break;
            case 'a': get(i).assertType(Array); got+='a'; break;
            case 'b': get(i).assertType(Blob); got+='b'; break;
            case 'u': get(i).assertType(Struct); got+='u'; break;
            default: got+='?'; ERROR("ignoring unknown format type '%c'", 
                       format[i]); break;
            }
        }
    } catch (...) {
        ERROR("parameter mismatch: expected '%s', got '%s...'",
              format, got.c_str());
        throw;
    }
}

#define VECTOR_GETTER(type, name, getter) \
    std::vector<type> AmArg::name() const { \
        std::vector<type> res; \
        for(size_t i=0;i<size();i++) \
            res.push_back(get(i).getter()); \
        return res; \
    }

VECTOR_GETTER(string, asStringVector, asCStr)
VECTOR_GETTER(int, asIntVector, asInt)
VECTOR_GETTER(bool, asBoolVector, asBool)
VECTOR_GETTER(double, asDoubleVector, asDouble)
VECTOR_GETTER(AmObject*, asAmObjectVector, asObject)

#undef  VECTOR_GETTER

std::vector<ArgBlob> AmArg::asArgBlobVector() const
{
    std::vector<ArgBlob> res;
    for(size_t i=0;i<size();i++)
        res.push_back(*get(i).asBlob());
    return res;
}

void PrintTo(const AmArg& arg, std::ostream* os)
{
    *os << arg.print();
}

AmArg &AmArg::assign_struct(std::initializer_list<std::pair<const std::string, AmArg> > l)
{
    invalidate();
    assertStruct();
    for(const auto &it: l) {
        v_struct->emplace(it.first, it.second);
    }
    INC_AMARGSTRUCT_SIZE(v_struct);
    return *this;
}

bool operator==(const AmArg& lhs, const AmArg& rhs)
{
    if(lhs.type != rhs.type)
        return false;

    switch(lhs.type) {
    case AmArg::Int:    { return lhs.v_int == rhs.v_int; } break;
    case AmArg::LongLong: { return lhs.v_long == rhs.v_long; } break;
    case AmArg::Bool:   { return lhs.v_bool == rhs.v_bool; } break;
    case AmArg::Double: { return lhs.v_double == rhs.v_double; } break;
    case AmArg::CStr:   { return !strcmp(lhs.v_cstr,rhs.v_cstr); } break;
    case AmArg::AObject:{ return lhs.v_obj == rhs.v_obj; } break;
    case AmArg::ADynInv:{ return lhs.v_inv == rhs.v_inv; } break;
    case AmArg::Array:  { return *lhs.v_array == *rhs.v_array;  } break;
    case AmArg::Struct: { return *lhs.v_struct == *rhs.v_struct;  } break;
    case AmArg::Blob:   {
        return (lhs.v_blob->len == rhs.v_blob->len) &&
               !memcmp(lhs.v_blob->data, rhs.v_blob->data, lhs.v_blob->len);
    } break;
    case AmArg::Undef: return true;
    default: assert(0);
    }
}

int arg2int(const AmArg &a)
{
    if(isArgInt(a)) return a.asInt();
    if(isArgLongLong(a)) return a.asLongLong();
    if(isArgDouble(a)) return a.asDouble();
    if(isArgBool(a)) return a.asBool();
    if(isArgCStr(a)) {
        int res;
        if(!str2int(a.asCStr(), res)) {
            throw std::string("can't convert arg to int: " + string(a.asCStr()));
        }
        return res;
    }
    throw std::string("can't convert arg to int");
}

string arg2str(const AmArg &a)
{
    switch(a.getType()) {
    case AmArg::Undef:
        return "";
    case AmArg::CStr:
        return a.asCStr();
    case AmArg::Int:
        return int2str(a.asInt());
    case AmArg::LongLong:
        return longlong2str(a.asLongLong());
    case AmArg::Double:
        return double2str(a.asDouble());
    case AmArg::Bool:
        return int2str(a.asBool());
    default:
        throw std::string("can't convert arg to string");
    }
}
