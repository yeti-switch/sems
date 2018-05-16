#include "RtcpStat.h"

#include <cmath>
#include <memory>

#include <strings.h>

MathStat::MathStat()
/*  : n(0),
    max(0),
    min(0),
    last(0),
    mean(0),
    variance_multiplied_by_n(0)*/
{
    bzero(this,sizeof(MathStat));
}

void MathStat::update(int v)
{
    float diff;

    last = v;

    if(n++) {
        if(min > v) min = v;
        if(max < v) max = v;
    } else {
        min = max = v;
    }

    diff = v-mean;
    mean += diff/n;

    variance_multiplied_by_n += diff*mean;
}

long double MathStat::sd() const
{
    if(n==0) return 0;
    return std::sqrt(variance_multiplied_by_n/n);
}
