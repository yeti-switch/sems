#ifndef _RSR_H_
#define _RSR_H_

namespace RSR {

enum DataType
{
    //number of last symbol (ASCII table) >:)
    DATA_SAMPLES = 0x73,
    DATA_META    = 0x61,
    DATA_NEW_META= 0x62,
    DATA_COMMON  = 0x6e
};

struct data_chunk
{
    unsigned int   type;
    unsigned int    size;
};

struct samples_data
{
    unsigned long long  ts;
    unsigned int        channel_id;
    unsigned int        sample_rate;
};

struct file_metadata
{
    unsigned long long offset;
};

struct file_new_metadata
{
    unsigned long long offset;
    unsigned long long offset_end;
};

struct common_data
{
    unsigned long long timestamp;
    unsigned long long meta_offset;
    unsigned int output_sample_rate;
};

struct chunk
{
    data_chunk header;
    union
    {
        common_data common;
        samples_data samples;
        file_metadata file;
        file_new_metadata new_file;
    } data;
};

}

#endif/*_RSR_H_*/
