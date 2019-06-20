#ifndef _RSR_H_
#define _RSR_H_

enum DataType
{
    //number of last symbol (ASCII table) >:)
    DATA_SAMPLES = 0x73,
    DATA_META    = 0x61
};

struct data_chunk
{
    unsigned char   type;
    unsigned int    size;
};

struct samples_data
{
    unsigned long long  ts;
    unsigned char       channel_id;
    unsigned int        sample_rate;
};

struct file_metadata
{
    unsigned long long offset;
};

struct chunk
{
    data_chunk header;
    union
    {
        samples_data samples;
        file_metadata file;
    } data;
};

#endif/*_RSR_H_*/
