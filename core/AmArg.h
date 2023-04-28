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

#pragma once

#include <assert.h>
#include <string.h>
#include <stdlib.h>

#include <vector>
#include <string>
#include <map>

#include "atomic_types.h"

/** base for Objects as @see AmArg parameter, not owned by AmArg (!) */
class AmObject {
  public:
    AmObject() { }
    virtual ~AmObject() { }
};

struct ArgBlob {
    void* data;
    int   len;

    ArgBlob();
    ArgBlob(const ArgBlob& a);
    ArgBlob(const void* _data, int _len);
    ~ArgBlob();
};

class AmDynInvoke;

/** \brief variable type argument for DynInvoke APIs */
class AmArg
  : public AmObject
{
    friend bool json2arg(std::istream& input, AmArg& res);
    friend bool operator==(const AmArg& lhs, const AmArg& rhs);

  public:
    struct OutOfBoundsException {
        OutOfBoundsException() { }
    };

    struct TypeMismatchException {
        TypeMismatchException() { }
    };

    enum Type {
        Undef = 0,
        Int,
        LongLong,
        Bool,
        Double,
        CStr,
        AObject, // pointer to an object not owned by AmArg
        ADynInv, // pointer to a AmDynInvoke (useful for call backs)
        Blob,
        Array,
        Struct,
        Reference
    };

    typedef std::map<std::string, AmArg> ValueStruct; 

  private:

    typedef std::vector<AmArg> ValueArray;

    struct ValueRef
      : public atomic_ref_cnt
    {
        AmObject *arg_ptr;

        ValueRef() = delete;
        ValueRef(const ValueRef &) = delete;
        ValueRef(AmObject *arg);

        void on_destroy();

        AmArg &arg() const;
    };

    Type type;

    // value
    union {
        long int      v_int;
        long long int v_long;
        bool          v_bool;
        double        v_double;
        const char*   v_cstr;
        AmObject*     v_obj;
        AmDynInvoke*  v_inv;
        ArgBlob*      v_blob;
        ValueArray*   v_array;
        ValueStruct*  v_struct;
        ValueRef*     v_ref;
    };

    void invalidate();

  public:

    AmArg();
    AmArg(const AmArg& v);
    AmArg(const int& v);
    AmArg(const long int& v);
    AmArg(const unsigned int& v);
    AmArg(const long unsigned int& v);
    AmArg(const long long int& v);
    AmArg(const bool& v);
    AmArg(const double& v);
    AmArg(const char* v);
    AmArg(const std::string &v);
    AmArg(const ArgBlob v);
    AmArg(AmObject* v, bool reference = false);
    AmArg(AmDynInvoke* v);

    // convenience constructors
    AmArg(std::vector<std::string>& v);
    AmArg(const std::vector<int>& v );
    AmArg(const std::vector<double>& v);
    AmArg(std::map<std::string, std::string>& v);
    AmArg(std::map<std::string, AmArg>& v);

    AmArg& operator=(const AmArg& rhs);

    ~AmArg();

    void clear();

    void assertArray();
    void assertArray(size_t s);
    void assertArray() const;

    void assertStruct();
    void assertStruct() const;

    void assertType(Type expected_type) const;

    template <Type _type_id> bool is() const {
        return type == _type_id;
    }
    bool isNumber() const;

    void setBorrowedPointer(AmObject* v);
    AmArg &getReferencedValue() const;

    int asInt() const { return (int)v_int; }
    long int asLong() const { return v_int; }
    long long asLongLong() const { return v_long; }
    bool asBool() const { return v_bool; }
    double asDouble() const { return v_double; }
    const char* asCStr() const { return v_cstr; }
    AmObject* asObject() const { return v_obj; }
    AmDynInvoke* asDynInv() const { return v_inv; }
    ArgBlob* asBlob() const { return v_blob; }
    ValueStruct* asStruct() const { return v_struct; }

    template <typename T> T asNumber() {
        switch(type) {
        case Int:
            return static_cast<T>(v_int);
        case LongLong:
            return static_cast<T>(v_long);
        case Double:
            return static_cast<T>(v_double);
        default:
            throw TypeMismatchException();
        }
    }

    size_t getAllocatedSize();

    short getType() const { return type; }
    const char* getTypeStr() const { return t2str(type); }
    static const char* t2str(int type);

    std::string print() const;
    static std::string print(const AmArg &a);

    // operations on arrays and structs

    size_t size() const;

    void push(const AmArg& a);
    void push(const std::string &key, const AmArg &val);
    void pop(AmArg &a);
    void pop_back(AmArg &a);
    void pop_back();
    void erase(size_t idx);

    void concat(const AmArg& a);

    /** throws OutOfBoundsException if array too small */
    AmArg& back();

    /** throws OutOfBoundsException if array too small */
    AmArg& back() const;

    /** throws OutOfBoundsException if array too small */
    AmArg& get(size_t idx);

    /** throws OutOfBoundsException if array too small */
    AmArg& get(size_t idx) const;

    /** resizes array if too small */
    AmArg& operator[](size_t idx);

    /** throws OutOfBoundsException if array too small */
    AmArg& operator[](size_t idx) const;

    /** resizes array if too small */
    AmArg& operator[](int idx);

    /** throws OutOfBoundsException if array too small */
    AmArg& operator[](int idx) const;

    AmArg& operator[](std::string key);
    AmArg& operator[](std::string key) const;
    AmArg& operator[](const char* key);
    AmArg& operator[](const char* key) const;

    /** Check for the existence of a struct member by name. */
    bool hasMember(const std::string& name) const;
    bool hasMember(const char* name) const;

    std::vector<std::string> enumerateKeys() const;
    ValueStruct::const_iterator begin() const;
    ValueStruct::const_iterator end() const;

    /** remove struct member */
    void erase(const char* name);

    /** remove struct member */
    void erase(const std::string& name);

    /**
      * throws exception if arg array does not conform to spec 
      *   i  - int 
      *   l  - long long
      *   t  - bool
      *   f  - double
      *   s  - cstr
      *   o  - object
      *   d  - dyninvoke
      *   b  - blob
      *   a  - array
      *   u  - struct
      *
      *   e.g. "ssif" -> [cstr, cstr, int, double]
      */
    void assertArrayFmt(const char* format) const;

    std::vector<std::string> asStringVector()const;
    std::vector<int> asIntVector() const;
    std::vector<bool> asBoolVector() const;
    std::vector<double> asDoubleVector() const;
    std::vector<AmObject*> asAmObjectVector() const;
    std::vector<ArgBlob> asArgBlobVector() const;
};

bool operator==(const AmArg& lhs, const AmArg& rhs);

int arg2int(const AmArg &a);
std::string arg2str(const AmArg &a);

//back compatiblity macro

#define define_isArg_assertArg(TYPE) \
    inline bool isArg ## TYPE(const AmArg &a) { return a.is<AmArg::TYPE>(); } \
    inline void assertArg ## TYPE(const AmArg &a) { a.assertType(AmArg::TYPE); }

define_isArg_assertArg(Undef)
define_isArg_assertArg(Int)
define_isArg_assertArg(LongLong)
define_isArg_assertArg(Bool)
define_isArg_assertArg(Double)
define_isArg_assertArg(CStr)
define_isArg_assertArg(AObject)
define_isArg_assertArg(ADynInv)
define_isArg_assertArg(Blob)
define_isArg_assertArg(Array)
define_isArg_assertArg(Struct)
define_isArg_assertArg(Reference)
