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

#include "AmAudioFile.h"
#include "AmPlugIn.h"
#include "AmUtils.h"
#include "AmSession.h"

#include <string.h>

AmAudioFileFormat::AmAudioFileFormat(const string& name, int subtype)
  : name(name), subtype(subtype), p_subtype(0)
{
  getSubtype();
  codec = getCodec();
    
  if(p_subtype && codec){
    rate = p_subtype->sample_rate;
    channels = p_subtype->channels;
    subtype = p_subtype->type;
  } 
  DBG("created AmAudioFileFormat of subtype %i, with rate %u, channels %u",
      subtype, rate, channels);
}

AmAudioFileFormat::AmAudioFileFormat(const string& name, int subtype, amci_subtype_t* p_subtype)
  : name(name), subtype(subtype), p_subtype(p_subtype)
{
  codec = getCodec();
    
  if(p_subtype && codec){
    rate = p_subtype->sample_rate;
    channels = p_subtype->channels;
  } 
  DBG("created AmAudioFileFormat of subtype %i, with rate %u, channels %u",
      subtype, rate, channels);
}

amci_codec_t* AmAudioFileFormat::getCodec()
{
  if(p_subtype && p_subtype->codec_id != codec_id){
    codec_id = p_subtype->codec_id;
    destroyCodec();
  }
  return AmAudioFormat::getCodec();
}

void AmAudioFileFormat::setSubtypeId(int subtype_id)  { 
  if (subtype != subtype_id) {
    DBG("changing file subtype to ID %d", subtype_id);
    destroyCodec();
    subtype = subtype_id; 
    p_subtype = 0;
    p_subtype = getSubtype();
    codec = getCodec();
  }
}

amci_subtype_t*  AmAudioFileFormat::getSubtype()
{
  if(!p_subtype && !name.empty()){
    // get file format from file name
    amci_inoutfmt_t* iofmt = AmPlugIn::instance()->fileFormat(name.c_str());
    if(!iofmt){
      ERROR("AmAudioFileFormat::getSubtype: file format '%s' does not exist",
	    name.c_str());
      return NULL;
    }

    p_subtype = AmPlugIn::instance()->subtype(iofmt,subtype);
    if(!p_subtype) {
      ERROR("AmAudioFileFormat::getSubtype: subtype %i in format '%s' does not exist",
	    subtype,iofmt->name);
      return NULL;
    }
 
    subtype = p_subtype->type;
  }
  return p_subtype;
}


AmAudioFileFormat* AmAudioFile::fileName2Fmt(const string& name, const string& subtype)
{
  string ext = file_extension(name);
  if(ext == ""){
    ERROR("fileName2Fmt: file name has no extension (%s)",name.c_str());
    return NULL;
  }

  iofmt = AmPlugIn::instance()->fileFormat("",ext);
  if(!iofmt){
    ERROR("fileName2Fmt: could not find a format with that extension: '%s'",ext.c_str());
    return NULL;
  }

  if (!subtype.empty()) {
    amci_subtype_t* st = AmPlugIn::instance()->subtype(iofmt, subtype);
    if (st!=NULL) {
      return new AmAudioFileFormat(iofmt->name, st->type, st);
    }
    WARN("subtype '%s' for file '%s' not found. Using default subtype",
	 subtype.c_str(), name.c_str());
  }

  return new AmAudioFileFormat(iofmt->name, -1);
}


int AmAudioFileFormat::getCodecId()
{
  if(!name.empty()){
    getSubtype();
    if(p_subtype)
      return p_subtype->codec_id;
  }
    
  return -1;
}

static ssize_t
memfile_write(void *c, const char *buf, size_t size)
{
    char *new_buff;
    struct memfile_cookie *cookie = (struct memfile_cookie*)c;

   /* Buffer too small? Keep doubling size until big enough */

   while (size + cookie->offset > cookie->allocated) {
        new_buff = (char*)realloc(cookie->buf, cookie->allocated * 2);
        if (new_buff == NULL) {
            return -1;
        } else {
            cookie->allocated *= 2;
            cookie->buf = new_buff;
        }
    }

   memcpy(cookie->buf + cookie->offset, buf, size);

   cookie->offset += size;
    if (cookie->offset > cookie->endpos)
        cookie->endpos = cookie->offset;

   return size;
}

static ssize_t
memfile_read(void *c, char *buf, size_t size)
{
    ssize_t xbytes;
    struct memfile_cookie *cookie = (struct memfile_cookie*)c;

   /* Fetch minimum of bytes requested and bytes available */

   xbytes = size;
    if (cookie->offset + size > cookie->endpos)
        xbytes = cookie->endpos - cookie->offset;
    if (xbytes < 0)     /* offset may be past endpos */
       xbytes = 0;

   memcpy(buf, cookie->buf + cookie->offset, xbytes);

   cookie->offset += xbytes;
    return xbytes;
}

static int
memfile_seek(void *c, off64_t *offset, int whence)
{
    off64_t new_offset;
    struct memfile_cookie *cookie =  (struct memfile_cookie*)c;

   if (whence == SEEK_SET)
        new_offset = *offset;
    else if (whence == SEEK_END)
        new_offset = cookie->endpos + *offset;
    else if (whence == SEEK_CUR)
        new_offset = cookie->offset + *offset;
    else
        return -1;

   if (new_offset < 0)
        return -1;

   cookie->offset = new_offset;
    *offset = new_offset;
    return 0;
}

static int
memfile_close(void *c)
{
    struct memfile_cookie *cookie = (struct memfile_cookie *)c;

   free(cookie->buf);
    cookie->allocated = 0;
    cookie->buf = NULL;

   return 0;
}

string AmAudioFile::getSubtype(string& filename) {
  string res;
  size_t dpos  = filename.rfind('|');
  if (dpos != string::npos) {
    res = filename.substr(dpos+1);
    filename = filename.substr(0, dpos);
  }
  return res;
}

void AmAudioFile::init(AmSession* session)
{
    session->setOutput(this);
}

// returns 0 if everything's OK
// return -1 if error
int  AmAudioFile::open(const string& filename, OpenMode mode, bool is_tmp)
{
  close();

  this->close_on_exit = true;
  on_close_done = false;

  FILE* n_fp = NULL;

  string f_name = filename;
  string subtype = getSubtype(f_name);

  AmAudioFileFormat* f_fmt = fileName2Fmt(filename, subtype);
  if(!f_fmt){
    ERROR("while trying to determine the format of '%s'",
	  filename.c_str());
    close();
    return -1;
  }
  fmt.reset(f_fmt);

  if(!is_tmp){
    n_fp = fopen(f_name.c_str(),mode == AmAudioFile::Read ? "r" : "w+");
    if(!n_fp){
      if(mode == AmAudioFile::Read)
	ERROR("file not found: %s",f_name.c_str());
      else
	ERROR("could not create/overwrite file: %s",f_name.c_str());
      return -1;
    }
  } else {
    memfile.allocated = get_cache_size();
    memfile.buf = (char*)malloc(memfile.allocated);
    cookie_io_functions_t  memfile_func = {
        .read  = memfile_read,
        .write = memfile_write,
        .seek  = memfile_seek,
        .close = memfile_close
    };
    n_fp = fopencookie(&memfile,"w+", memfile_func);
    if(!n_fp){
      ERROR("could not create temporary file: %s",strerror(errno));
      return -1;
    }
  }

  return fpopen_int(f_name, mode, n_fp, subtype);
}

int AmAudioFile::fpopen(const string& filename, OpenMode mode, FILE* n_fp)
{
  close();
  on_close_done = false;
  string f_name = filename;
  string subtype = getSubtype(f_name);

  AmAudioFileFormat* f_fmt = fileName2Fmt(filename, subtype);
  if(!f_fmt){
    ERROR("while trying to determine the format of '%s'",
	  filename.c_str());
    close();
    return -1;
  }
  fmt.reset(f_fmt);

  return fpopen_int(f_name, mode, n_fp, subtype);
}

int AmAudioFile::fpopen_int(const string& filename, OpenMode mode, 
			    FILE* n_fp, const string& subtype)
{
  (void)subtype;
  _filename = filename;
  open_mode = mode;
  fp = n_fp;
  fseek(fp,0L,SEEK_SET);

  amci_file_desc_t fd;
  memset(&fd, 0, sizeof(amci_file_desc_t));

  int ret = -1;
  
  AmAudioFileFormat* f_fmt = static_cast<AmAudioFileFormat*>(fmt.get());
  if(open_mode == AmAudioFile::Write){

  if (f_fmt->channels<0)
    ERROR("channel count must be set for output file.");
    close();
    return -1;
  }

  fd.subtype = f_fmt->getSubtypeId();
  fd.channels = f_fmt->channels;
  fd.rate = f_fmt->getRate();

  if( iofmt->open && 
      !(ret = (*iofmt->open)(fp, &fd, mode, f_fmt->getHCodecNoInit())) ) {

    if (mode == AmAudioFile::Read) {
      f_fmt->setSubtypeId(fd.subtype);
      f_fmt->channels = fd.channels;
      f_fmt->setRate(fd.rate);
      data_size = fd.data_size;

      setBufferSize(fd.buffer_size, fd.buffer_thresh, fd.buffer_full_thresh);
    }
    begin = ftell(fp);
  } else {
    if(!iofmt->open)
      ERROR("no open function");
    else
      ERROR("open returned %d: %s", ret, strerror(errno));
    close();
    return ret;
  }

  return ret;
}

AmAudioFile::AmAudioFile()
  : AmBufferedAudio(0, 0, 0), data_size(0),
    fp(0), begin(0), loop(false), autorewind(false),
    on_close_done(false),
    close_on_exit(true)
{
  memset(&memfile, 0, sizeof(memfile));
}

AmAudioFile::~AmAudioFile()
{
  close();
}

void AmAudioFile::rewind()
{
  fseek(fp,begin,SEEK_SET);
  clearBufferEOF();
}

void AmAudioFile::rewind(unsigned int msec)
{
  long fpos = ftell(fp);
  long int k = fmt->calcBytesToRead(((getSampleRate()/100)*msec)/10);
  
  if(fpos > begin + k) {
    DBG("Rewinding %d milliseconds (%ld bytes)", msec, k);
    fseek(fp, -k, SEEK_CUR);
  } else {
    DBG("Rewinding file");
    fseek(fp, begin, SEEK_SET);
  }
  clearBufferEOF();
}

void AmAudioFile::forward(unsigned int msec)
{
  long fpos = ftell(fp);
  long int k = fmt->calcBytesToRead(((getSampleRate()/100)*msec)/10);
  
  if(fpos <= (data_size - k)) {
    DBG("Forwarding %d milliseconds (%ld bytes)", msec, k);
    fseek(fp, k, SEEK_CUR);
    clearBufferEOF();
  } else {
    DBG("Forwarding to EOF");
    fseek(fp, data_size, SEEK_SET);
  }
}

void AmAudioFile::on_close()
{
  if(fp && !on_close_done){

    AmAudioFileFormat* f_fmt = 
      dynamic_cast<AmAudioFileFormat*>(fmt.get());

    if(f_fmt){
      amci_file_desc_t fmt_desc = { f_fmt->getSubtypeId(), 
				    (int)f_fmt->getRate(),
				    f_fmt->channels, 
				    data_size ,
				    0, 0, 0};
	    
      if(!iofmt){
	ERROR("file format pointer not initialized: on_close will not be called");
      }
      else if(iofmt->on_close)
	(*iofmt->on_close)(fp,&fmt_desc,open_mode, fmt->getHCodecNoInit(), fmt->getCodec());      
    }

    if(open_mode == AmAudioFile::Write){

      DBG("After close:");
      DBG("fmt::subtype = %i",f_fmt->getSubtypeId());
      DBG("fmt::channels = %i",f_fmt->channels);
      DBG("fmt::rate = %i",f_fmt->getRate());
    }

    on_close_done = true;
  }
}


void AmAudioFile::close()
{
  if(fp){
    on_close();
    if(close_on_exit) {
      fflush(fp);
      fclose(fp);
    }
    fp = 0;
  }
}

string AmAudioFile::getMimeType()
{
  if(!iofmt)
    return "";
    
  return iofmt->email_content_type;
}


int AmAudioFile::read(unsigned int user_ts, unsigned int size)
{
  if(!fp){
    ERROR("AmAudioFile::read: file is not opened");
    return -1;
  }

  int ret;
  int s = size;

 read_block:
  long fpos  = ftell(fp);
  if(data_size < 0 || fpos - begin < data_size){
    
    if((data_size > 0) && (fpos - begin + (int)size > data_size)) {
      // last block to read
      s = data_size - fpos + begin;
    }
    
    if ((data_size == -1) && loop.get() && feof(fp)) {
      // data size unknown, loop and eof
      DBG("rewinding audio file...");
      rewind();
      goto read_block;
    }

    if (data_size == -1 && autorewind.get() && feof(fp)) {
      // data size unknown, autorewind and eof      
      DBG("autorewinding audio file...");
      rewind();

      ret = -2; // eof
    } else {
      // read from file
      int rs = fread((void*)((unsigned char*)samples),1,s,fp);
      if (rs != s) {
        DBG("marking data size as invalid as we read %d but should read %d", rs, s);
        // we read less than we should => data size is probably broken
        data_size = -1;
        s = rs;
      }
    
      ret = (!ferror(fp) ? s : -1);
    }

#if (defined(__BYTE_ORDER) && (__BYTE_ORDER == __BIG_ENDIAN))
#define bswap_16(A)  ((((u_int16_t)(A) & 0xff00) >> 8) | \
		      (((u_int16_t)(A) & 0x00ff) << 8))
    
    unsigned int i;
    for(i=0;i<=size/2;i++) {
      ((u_int16_t *)((unsigned char*)samples))[i]=
	bswap_16(((u_int16_t *)((unsigned char*)samples))[i]);
    }
    
#endif
  } else {
    if (loop.get() && data_size>0) {
      DBG("rewinding audio file...");
      rewind();
      goto read_block;
    }

    if (autorewind.get() && data_size>0){
      DBG("autorewinding audio file...");
      rewind();
    }
    
    ret = -2; // eof
  }

  if(ret > 0 && s > 0 && (unsigned int)s < size){
    DBG("0-stuffing packet: adding %i bytes (packet size=%i)",size-s,size);
    memset((unsigned char*)samples + s,0,size-s);
    return size;
  }

  return ret;
}

int AmAudioFile::write(unsigned int user_ts, unsigned int size)
{
  if(!fp){
    ERROR("AmAudioFile::write: file is not opened");
    return -1;
  }

  if (getMode() != AmAudioFile::Write) {
    return size;
  }

  int s = fwrite((void*)((unsigned char*)samples),1,size,fp);
  if(s>0)
    data_size += s;
  return (!ferror(fp) ? s : -1);
}

int AmAudioFile::getLength()
{ 
  if (!data_size || !fmt.get())
    return 0;

  float rate = fmt->getRate() / 1000;
  return (int) (fmt->bytes2samples(data_size)  / rate);
}
