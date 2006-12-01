/*
 * $Id: AmDtmfDetector.h,v 1.1.2.1 2005/06/01 12:00:24 rco Exp $
 *
 * Copyright (C) 2006 Sippy Software, Inc.
 *
 * This file is part of sems, a free SIP media server.
 *
 * sems is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version
 *
 * For a license to use the ser software under conditions
 * other than those described here, or to purchase support for this
 * software, please contact iptel.org by e-mail at the following addresses:
 *    info@iptel.org
 *
 * sems is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License 
 * along with this program; if not, write to the Free Software 
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#ifndef _AmJitterBuffer_h_
#define _AmJitterBuffer_h_

#include "AmThread.h"
#include "AmRtpPacket.h"

#include <map>
using std::map;

template <typename T> class RingBuffer
{
private:
    T *m_buffer;
    unsigned int m_size;

public:
    RingBuffer(unsigned int size);
    ~RingBuffer();
    void put(unsigned int idx, const T*);
    void get(unsigned int idx, T*);
    void clear(unsigned int idx);
};

class AmJitterBuffer
{
private:
    AmMutex m_mutex;
    RingBuffer<AmRtpPacket> m_ringBuffer;
    bool m_tsInited;
    unsigned int m_lastTs;
    unsigned int m_tsDelta;
    bool m_tsDeltaInited;
    int m_delayCount;
    unsigned int m_jitter;
    unsigned int m_frameSize;

public:
    AmJitterBuffer(unsigned int frame_size);
    void put(const AmRtpPacket *);
    bool get(AmRtpPacket &, unsigned int ts);
};

template <typename T>
RingBuffer<T>::~RingBuffer()
{
    delete [] m_buffer;
}


#endif // _AmJitterBuffer_h_
