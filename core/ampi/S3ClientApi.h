#pragma once

#include "AmEvent.h"

#include <string>
using std::string;

#define S3CLIENT_QUEUE  "s3client"

class S3Event : public AmEvent
{
public:
    enum Type {
        GetFileInfo = 0,
        GetFilePart,
        FileInfo,
        FilePart,
        FileError,

        MaxType
    };

    S3Event(int event_id) : AmEvent(event_id){}
    virtual ~S3Event(){}
};

class S3GetFileInfo : public S3Event
{
public:
    string name;
    string sender_id;
    AmArg info;

    S3GetFileInfo(const string& name_, string session_id)
        : S3Event(GetFileInfo)
        , name(name_)
        , sender_id(session_id){}

    void setInfo(const AmArg& info_) {
        info = info_;
    }
};

class S3FileInfo : public S3Event
{
public:
    string name;
    AmArg info;

    S3FileInfo(const string& name_, AmArg info_)
        : S3Event(FileInfo)
        , name(name_)
        , info(info_){}
};

class S3GetFilePart : public S3Event
{
public:
    string name;
    string sender_id;
    string version_id;
    uint64_t start;
    uint64_t size;

    S3GetFilePart(const string& name_, const string& version, const string& session_id, uint64_t start_, uint64_t size_)
      : S3Event(GetFilePart),
        name(name_),
        sender_id(session_id),
        version_id(version),
        start(start_),
        size(size_)
    {}
};

class S3FilePart : public S3Event
{
public:
    string name;
    uint64_t start;
    uint64_t size;
    char* data;

    S3FilePart(const string& name_, uint64_t start_, uint64_t size_, char* data_)
    : S3Event(FilePart)
    , name(name_)
    , start(start_)
    , size(size_)
    , data(data_){}
    ~S3FilePart() {
        delete[] data;
    }
};

class S3FileError : public S3Event
{
public:
    string name;
    AmArg error;

    S3FileError(const string& name_, AmArg error_)
        : S3Event(FileError)
        , name(name_)
        , error(error_){}
};
