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

/* this whole module is only needed to convert from host to network
   byte order, otherwise CODEC_PCM16 could be used right away
*/

// For ntohs() on Solaris.
#if defined (__SVR4) && defined (__sun)
#include <sys/byteorder.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <inttypes.h>
#endif

#include <arpa/inet.h>

#include "amci.h"
#include "codecs.h"
#include "../../log.h"

static int Pcm16_2_L16(unsigned char* out_buf, unsigned char* in_buf, unsigned int size,
		       unsigned int channels, unsigned int rate, long h_codec);

static int L16_2_Pcm16(unsigned char* out_buf, unsigned char* in_buf, unsigned int size,
		       unsigned int channels, unsigned int rate, long h_codec);

static unsigned int L16_bytes2samples(long, unsigned int);
static unsigned int L16_samples2bytes(long, unsigned int);

BEGIN_EXPORTS( "l16" , AMCI_NO_MODULEINIT, AMCI_NO_MODULEDESTROY )

  BEGIN_CODECS
    CODEC( CODEC_L16, Pcm16_2_L16, L16_2_Pcm16,
           AMCI_NO_CODEC_PLC, AMCI_NO_CODECCREATE, AMCI_NO_CODECDESTROY,
           L16_bytes2samples, L16_samples2bytes )
  END_CODECS

  BEGIN_PAYLOADS
#if SYSTEM_SAMPLECLOCK_RATE >= 32000
	PAYLOAD( -1, "L16", 32000, 32000, 1, CODEC_L16, AMCI_PT_AUDIO_LINEAR )
    PAYLOAD( -1, "L16", 24000, 24000, 1, CODEC_L16, AMCI_PT_AUDIO_LINEAR )
#endif
#if SYSTEM_SAMPLECLOCK_RATE >= 16000
	PAYLOAD( -1, "L16", 16000, 16000, 1, CODEC_L16, AMCI_PT_AUDIO_LINEAR )
#endif
	PAYLOAD( -1, "L16",  8000,  8000, 1, CODEC_L16, AMCI_PT_AUDIO_LINEAR )
  END_PAYLOADS

  BEGIN_FILE_FORMATS
  END_FILE_FORMATS

END_EXPORTS

static unsigned int L16_bytes2samples(long h_codec, unsigned int num_bytes)
{
  return num_bytes / 2;
}

static unsigned int L16_samples2bytes(long h_codec, unsigned int num_samples)
{
  return num_samples * 2;
}

static int L16_2_Pcm16( unsigned char* out_buf, unsigned char* in_buf, unsigned int size,
			 unsigned int channels, unsigned int rate, long h_codec )
{
  short* out_b = (short*)out_buf;
  short* in_b  = (short*)in_buf;
  short* end   = in_b + size / 2;

  while(in_b != end)
    *(out_b++) = ntohs(*(in_b++));
  
  return size;
}


static int Pcm16_2_L16( unsigned char* out_buf, unsigned char* in_buf, unsigned int size,
			unsigned int channels, unsigned int rate, long h_codec )
{
  short* out_b         = (short*)out_buf;
  short* in_b          = (short*)(in_buf);
  short* end           = in_b + size / 2;

  while(in_b != end)
    *(out_b++) = htons(*(in_b++));

  return size;
}


