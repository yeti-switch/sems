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

/** @file AmUtils.cpp */

#include "AmUtils.h"
#include "AmThread.h"
#include "AmConfig.h"
#include "log.h"
#include "AmSipMsg.h"
#include "sip/resolver.h"
#include "sip/ip_util.h"
#include "sip/parse_common.h"

#include <stdarg.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <assert.h>

#include <sys/socket.h>
#include <sys/un.h>

#include <regex.h>
#include <algorithm>

#include <fstream>


static char _int2str_lookup[] = { '0', '1', '2', '3', '4', '5', '6' , '7', '8', '9' };

void update_min_max(double &min, double &max, double v)
{
    if(v > max)
        max = v;

    if(min) {
        if(v < min)
            min = v;
    } else {
        min = v;
    }
}

string timeval2str(const timeval &tv)
{
  time_t t;
  struct tm tt;
  char s[64] = {0};

  t = tv.tv_sec;
  localtime_r(&t,&tt);
  int len = strftime(s, sizeof s, "%Y-%m-%d %H:%M:%S", &tt);
  if(len>0) return string(s,len);
  return string("conversion error");
}

string timeval2str_ntp(const timeval &tv)
{
  time_t t;
  struct tm tt;
  int time_len, date_len, s_len;
  char time[10] = {0}, date[24] = {0}, s[64];

  t = tv.tv_sec;
  localtime_r(&t,&tt);

  time_len = strftime(time, sizeof time, "%H:%M:%S", &tt);
  date_len = strftime(date, sizeof date, "%Z %a %b %d %Y", &tt);
  s_len = snprintf(s,sizeof s,"%.*s.%03d %.*s",
                   time_len,time,
                   (int)(tv.tv_usec/1000),
                   date_len,date);
  return string(s,s_len);
}

string timeval2str_usec(const timeval &tv)
{
	char s[64] = {0};
	int len = snprintf(s, sizeof s, "%ld.%06ld", tv.tv_sec, tv.tv_usec);
	if(len>0) return string(s,len);
	return string("conversion error");
}

double timeval2double(const timeval &tv)
{
	return tv.tv_sec + tv.tv_usec/(double)1e6;
}

string int2str(unsigned int val)
{
  char buffer[64] = {0};
  int i=62;
  lldiv_t d;

  d.quot = val;
  do{
    d = lldiv(d.quot,10);
    buffer[i] = _int2str_lookup[d.rem];
  }while(--i && d.quot);

  return string((char*)(buffer+i+1));
}

template<class T, class DT>
string signed2str(T val, T (*abs_func) (T), DT (*div_func) (T, T))
{
  char buffer[64] = {0,0};
  int i=62;
  DT d;

  d.quot = abs_func(val);
  do{
    d = div_func(d.quot,10);
    buffer[i] = _int2str_lookup[d.rem];
  }while(--i && d.quot);

  if (i && (val<0)) {
    buffer[i]='-';
    i--;
  }

  return string((char*)(buffer+i+1));
}

string int2str(int val) { return signed2str<int, div_t>(val, abs, div); }
string long2str(long int val) { return signed2str<long, ldiv_t>(val, labs, ldiv); }
string longlong2str(long long int val) { return signed2str<long long, lldiv_t>(val, llabs, lldiv); }

void longlong2timespec(struct timespec &ts,unsigned long long msec)
{
  if(0==msec){
    ts.tv_sec = 0;
    ts.tv_nsec = 0;
    return;
  }
  ts.tv_sec = (time_t)(msec / 1000000ULL);
  ts.tv_nsec = (long)(1000ULL*(msec % 1000000ULL));
}

static char _int2hex_lookup[] = { '0', '1', '2', '3', '4', '5', '6' , '7', '8', '9','A','B','C','D','E','F' };
static char _int2hex_lookup_l[] = { '0', '1', '2', '3', '4', '5', '6' , '7', '8', '9','a','b','c','d','e','f' };

string char2hex(unsigned char val, bool lowercase)
{
  string res;
  if (lowercase) {
    res += _int2hex_lookup_l[val >> 4];
    res += _int2hex_lookup_l[val & 0x0f];
  } else {
    res += _int2hex_lookup[val >> 4];
    res += _int2hex_lookup[val & 0x0f];
  }
  return res;
}

string int2hex(unsigned int val, bool lowercase)
{
  unsigned int digit=0;

  char buffer[2*sizeof(int)+1] = {0};
  int i,j=0;

  for(i=0; i<int(2*sizeof(int)); i++){
    digit = val >> 4*(2*sizeof(int)-1);
    val = val << 4;
    buffer[j++] = lowercase ?
      _int2hex_lookup_l[(unsigned char)digit] : _int2hex_lookup[(unsigned char)digit];
  }

  return string((char*)buffer);
}

string long2hex(unsigned long val)
{
  unsigned int digit=0;

  char buffer[2*sizeof(long)+1] = {0};
  int i,j=0;

  for(i=0; i<int(2*sizeof(long)); i++){
    digit = val >> 4*(2*sizeof(long)-1);
    val = val << 4;
    buffer[j++] = _int2hex_lookup[(unsigned char)digit];
  }

  return string((char*)buffer);
}

/** Convert a double to a string. (from jsoncpp) */
string double2str(double val) {
  char buffer[32];
  sprintf(buffer, "%#.16g", val); 
  char* ch = buffer + strlen(buffer) - 1;
  if (*ch != '0') return buffer; // nothing to truncate, so save time
  while(ch > buffer && *ch == '0'){
    --ch;
  }
  char* last_nonzero = ch;
  while(ch >= buffer){
    switch(*ch){
    case '0':
    case '1':
    case '2':
    case '3':
    case '4':
    case '5':
    case '6':
    case '7':
    case '8':
    case '9':
      --ch;
      continue;
    case '.':
      // Truncate zeroes to save bytes in output, but keep one.
      *(last_nonzero+2) = '\0';
      return string(buffer);
    default:
      return string(buffer);
    }
  }
  return string(buffer);
}

/**
 * Convert a reversed hex string to uint.
 * @param str    [in]  string to convert.
 * @param result [out] result integer.
 * @return true if failed. 
 */
bool reverse_hex2int(const string& str, unsigned int& result)
{
  result=0;
  char mychar;

  for (string::const_reverse_iterator pc = str.rbegin();
       pc != str.rend(); ++pc) {

    result <<= 4;
    mychar=*pc;

    if ( mychar >='0' && mychar <='9') 
      result += mychar -'0';
    else if (mychar >='a' && mychar <='f') 
      result += mychar -'a'+10;
    else if (mychar  >='A' && mychar <='F') 
      result += mychar -'A'+10;
    else 
      return true;
  }

  return false;
}

bool str2i(const string& str, unsigned int& result)
{
  char* s = (char*)str.c_str();
  return str2i(s,result);
}

bool str2i(char*& str, unsigned int& result, char sep)
{
  unsigned int ret=0;
  int i=0;
  char* init = str;

  for(; (*str != '\0') && (*str == ' '); str++);

  for(; *str != '\0';str++){
    if ( (*str <= '9' ) && (*str >= '0') ){
      ret=ret*10+*str-'0';
      i++;
      if (i>10) goto error_digits;
    } else {

      bool eol = false;
      switch(*str){
      case 0xd:
      case 0xa:
      case 0x0:
	eol = true;
      }

      if( (*str != sep) && !eol )
	goto error_char;

      break;
    }
  }

  result = ret;
  return false;

 error_digits:
  DBG("str2i: too many letters in [%s]\n", init);
  return true;
 error_char:
  DBG("str2i: unexpected char 0x%x in %s\n", *str, init);
  return true;
}

bool str2int(const string& str, int& result)
{
  char* s = (char*)str.c_str();
  return str2int(s,result);
}

bool str2int(char*& str, int& result, char sep)
{
  int ret=0;
  int i=0;
  char* init = str;
  int sign = 1;

  for(; (*str != '\0') && (*str == ' '); str++);

  if (*str == '-') {
    sign = -1;
    str++;
    for(; (*str != '\0') && (*str == ' '); str++);
  }

  for(; *str != '\0';str++){
    if ( (*str <= '9' ) && (*str >= '0') ){
      ret=ret*10+*str-'0';
      i++;
      if (i>10) goto error_digits;
    } else {

      bool eol = false;
      switch(*str){
      case 0xd:
      case 0xa:
      case 0x0:
	eol = true;
      }

      if( (*str != sep) && !eol )
	goto error_char;

      break;
    }
  }

  result = ret * sign;
  return true;

 error_digits:
  DBG("str2int: too many digits in [%s]\n", init);
  return false;
 error_char:
  DBG("str2i: unexpected char 0x%x in %s\n", *str, init);
  return false;
}

// long int could probably be the same size as int
bool str2long(const string& str, long& result)
{
  char* s = (char*)str.c_str();
  return str2long(s,result);
}

bool str2long(char*& str, long& result, char sep)
{
  long ret=0;
  int i=0;
  char* init = str;
  long sign = 1;

  for(; (*str != '\0') && (*str == ' '); str++);

  if (*str == '-') {
    sign = -1;
    str++;
    for(; (*str != '\0') && (*str == ' '); str++);
  }

  for(; *str != '\0';str++){
    if ( (*str <= '9' ) && (*str >= '0') ){
      ret=ret*10+*str-'0';
      i++;
      if (i>20) goto error_digits;
    } else {

      bool eol = false;
      switch(*str){
      case 0xd:
      case 0xa:
      case 0x0:
	eol = true;
      }

      if( (*str != sep) && !eol )
	goto error_char;

      break;
    }
  }

  result = ret * sign;
  return true;

 error_digits:
  DBG("str2long: too many digits in [%s]\n", init);
  return false;
 error_char:
  DBG("str2long: unexpected char 0x%x in %s\n", *str, init);
  return false;
}

bool str2bool(const string &s, bool &dst)
{
  // TODO: optimize
  if ((s == "yes") || (s == "true") || (s == "1")) {
    dst = true;
    return true;
  }
  if ((s == "no") || (s == "false") || (s == "0")) {
    dst = false;
    return true;
  }
  return false;
}

bool str2longlong(const string& str, long long& result)
{
  char* s = (char*)str.c_str();
  return str2longlong(s,result);
}

bool str2longlong(char*& str, long long& result, char sep)
{
  long long ret=0;
  int i=0;
  char* init = str;
  long sign = 1;

  for(; (*str != '\0') && (*str == ' '); str++);

  if (*str == '-') {
    sign = -1;
    str++;
    for(; (*str != '\0') && (*str == ' '); str++);
  }

  for(; *str != '\0';str++){
    if ( (*str <= '9' ) && (*str >= '0') ){
      ret=ret*10+*str-'0';
      i++;
      if (i>20) goto error_digits;
    } else {

      bool eol = false;
      switch(*str){
      case 0xd:
      case 0xa:
      case 0x0:
    eol = true;
      }

	  if( (*str != sep) && !eol )
	goto error_char;

      break;
    }
  }

  result = ret * sign;
  return true;

 error_digits:
  DBG("str2long: too many digits in [%s]\n", init);
  return false;
 error_char:
  DBG("str2long: unexpected char 0x%x in %s\n", *str, init);
  return false;
}

std::string URL_decode(const std::string& s) {
  enum {
    uSNormal=       0, // start
    uSH1,
    uSH2
  };

  int st = uSNormal;
  string res;
  for (size_t pos = 0; pos < s.length(); pos++) {
    switch (st) {
    case uSNormal: {
      if (s[pos] == '%')
	st = uSH1;
      else
	res+=s[pos];

    }; break;

    case uSH1: {
      if (s[pos] == '%') {
	res+='%';
	st = uSNormal;
      } else {
      st = uSH2;
      }
    }; break;

    case uSH2: {
      char c = 0;

      if ( s[pos] >='0' && s[pos] <='9')
	c += s[pos] -'0';
      else if (s[pos] >='a' && s[pos] <='f')
	c += s[pos] -'a'+10;
      else if (s[pos]  >='A' && s[pos] <='F')
	c += s[pos] -'A'+10;
      else {
	st = uSNormal;
	DBG("error in escaped string: %%%c%c\n", s[pos-1], s[pos]);
	continue;
      }

      if ( s[pos-1] >='0' && s[pos-1] <='9')
	c += (s[pos-1] -'0') << 4;
      else if (s[pos-1] >='a' && s[pos-1] <='f')
	c += (s[pos-1] -'a'+10) << 4;
      else if (s[pos-1]  >='A' && s[pos-1] <='F')
	c += (s[pos-1] -'A'+10 ) << 4;
      else {
	st = uSNormal;
	DBG("error in escaped string: %%%c%c\n", s[pos-1], s[pos]);
	continue;
      }
      res +=c;
      st = uSNormal;
    } break;
    }
  }

  return res;
}


std::string URL_encode(const std::string &s)
{
    const std::string unreserved = "-_.~";

    std::string escaped="";
    for(size_t i=0; i<s.length(); i++)
    {

      //RFC 3986 section 2.3 Unreserved Characters (January 2005)
      if ((s[i] >= 'A' && s[i] <= 'Z')
	  || (s[i] >= 'a' && s[i] <= 'z')
	  || (s[i] >= '0' && s[i] <= '9')
	  || (s[i] == '-') || (s[i] == '_') || (s[i] == '.') || (s[i] == '~') )
        {
            escaped.push_back(s[i]);
        }
        else
        {
            escaped.append("%");
            char buf[3];
            sprintf(buf, "%.2X", s[i]);
            escaped.append(buf);
        }
    }
    return escaped;
}

int parse_return_code(const char* lbuf, unsigned int& res_code, string& res_msg )
{
  char res_code_str[4] = {'\0'};
  const char* cur=lbuf;

  // parse xxx code
  for( int i=0; i<3; i++ ){
    if( (*cur >= '0') && (*cur <= '9') )
      res_code_str[i] = *cur;
    else
      goto error;
    cur++;
  }

  if( (*cur != ' ') && (*cur != '\t') && (*cur !='-') ){
    ERROR("expected 0x%x or 0x%x or 0x%x, found 0x%x\n",' ','\t','-',*cur);
    goto error;
  }

  if(sscanf(res_code_str,"%u",&res_code) != 1){
    ERROR("wrong code (%s)\n",res_code_str);
    goto error;
  }

  // wrap spaces and tabs
  while( (*cur == ' ') || (*cur == '\t') || (*cur =='-')) 
    cur++;

  res_msg = cur;
  return 0;

 error:
  ERROR("while parsing response\n");
  return -1;
}

bool file_exists(const string& name)
{
  FILE* test_fp = fopen(name.c_str(),"r");
  if(test_fp){
    fclose(test_fp);
    return true;
  }
  return false;
}

string filename_from_fullpath(const string& path)
{
  string::size_type pos = path.rfind('/');
  if(pos != string::npos)
    return path.substr(pos+1);
  return "";
}

string get_addr_str(const sockaddr_storage* addr)
{
  char host[NI_MAXHOST] = "";
  return am_inet_ntop(addr,host,NI_MAXHOST);
}

string get_addr_str_sip(const sockaddr_storage* addr)
{
  char host[NI_MAXHOST] = "";
  return am_inet_ntop_sip(addr,host,NI_MAXHOST);
}

string file_extension(const string& path)
{
  string::size_type pos = path.rfind('.');
  if(pos == string::npos){
    pos = path.rfind("%2E");

    if(pos == string::npos)
      return "";
    return path.substr(pos+3,string::npos);
  }

  return path.substr(pos+1,string::npos);
}

string add2path( const string& path, int n_suffix, ...)
{
  va_list ap;
  string outpath = path;
    
  va_start(ap,n_suffix);

  for(int i=0; i<n_suffix; i++){

    const char* s = va_arg(ap,const char*);

    if(!outpath.empty() && (outpath[outpath.length()-1] != '/'))
      outpath += '/';

    outpath += s;
  }

  va_end(ap);

  return outpath;
}

int get_local_addr_for_dest(sockaddr_storage* remote_ip, sockaddr_storage* local)
{
  int temp_sock = socket(remote_ip->ss_family, SOCK_DGRAM, 0 );
  if (temp_sock == -1) {
    ERROR("socket() failed: %s\n",
	  strerror(errno));
    return -1;
  }

  socklen_t len=sizeof(sockaddr_storage);
  if (connect(temp_sock, (sockaddr*)remote_ip, 
	      remote_ip->ss_family == AF_INET ? 
	      sizeof(sockaddr_in) : sizeof(sockaddr_in6))==-1) {

      ERROR("connect failed: %s\n",
	    strerror(errno));
      goto error;
  }

  if (getsockname(temp_sock, (sockaddr*)local, &len)==-1) {
      ERROR("getsockname failed: %s\n",
	    strerror(errno));
      goto error;
  }

  close(temp_sock);
  return 0;

 error:
  close(temp_sock);
  return -1;
}

int get_local_addr_for_dest(const string& remote_ip, string& local)
{
  sockaddr_storage remote_ip_ss;
  sockaddr_storage local_ss;

  int err = inet_pton(AF_INET,remote_ip.c_str(),&((sockaddr_in*)&remote_ip_ss)->sin_addr);
  if(err == 1){
    remote_ip_ss.ss_family = AF_INET;
  }
  else if(err == 0){
    err = inet_pton(AF_INET6,remote_ip.c_str(),&((sockaddr_in6*)&remote_ip_ss)->sin6_addr);
    if(err == 1){
      remote_ip_ss.ss_family = AF_INET6;
    }
  }

  if(err == 0){
    // not an IP... try a name.
    dns_handle dh;
    err = resolver::instance()->resolve_name(remote_ip.c_str(),&dh,&remote_ip_ss,IPv4);
  }

  if(err == -1){
    ERROR("While converting address: '%s'",remote_ip.c_str());
    return -1;
  }

  if(remote_ip_ss.ss_family==AF_INET){
#if defined(BSD44SOCKETS)
    ((sockaddr_in*)&remote_ip_ss)->sin_len = sizeof(sockaddr_in);
#endif
    ((sockaddr_in*)&remote_ip_ss)->sin_port = htons(5060); // fake port number
  }
  else {
#if defined(BSD44SOCKETS)
    ((sockaddr_in6*)&remote_ip_ss)->sin6_len = sizeof(sockaddr_in6);
#endif
    ((sockaddr_in6*)&remote_ip_ss)->sin6_port = htons(5060); // fake port number
  }

  err = get_local_addr_for_dest(&remote_ip_ss, &local_ss);
  if(err < 0){
    return -1;
  }

  char tmp_addr[NI_MAXHOST];
  if(am_inet_ntop(&local_ss,tmp_addr,NI_MAXHOST) != NULL){
    local = tmp_addr;
    return 0;
  }
  
  return -1;
}

string extract_tag(const string& addr)
{
  string::size_type p = addr.find(";tag=");
  if(p == string::npos)
    return "";

  p += 5/*sizeof(";tag=")*/;
  string::size_type p_end = p;
  while(p_end < addr.length()){
    if( addr[p_end] == '>'
	|| addr[p_end] == ';' )
      break;
    p_end++;
  }
  return addr.substr(p,p_end-p);
}

bool key_in_list(const string& s_list, const string& key, 
		 char list_delim) 
{
  size_t pos = 0;
  size_t pos2 = 0;
  size_t pos_n = 0;
  while (pos < s_list.length()) {
    pos_n = pos2 = s_list.find(list_delim, pos);
    if (pos2==string::npos)
      pos2 = s_list.length()-1;
    while ((pos2>0)&&
	   ((s_list[pos2] == ' ')||(s_list[pos2] == list_delim)
	    ||(s_list[pos2] == '\n')))
      pos2--;
    if (s_list.substr(pos, pos2-pos+1)==key)
      return true;
    if (pos_n == string::npos)
      return false;
    while ((pos_n<s_list.length()) && 
	   ((s_list[pos_n] == ' ')||(s_list[pos_n] == list_delim)||
	    (s_list[pos_n] == '\n')))
      pos_n++;
    if (pos_n == s_list.length())
      return false;
    pos = pos_n;
  }
  return false;
}

string strip_header_params(const string& hdr_string) 
{
  size_t val_begin = 0; // skip trailing ' '
  for (;(val_begin<hdr_string.length()) && 
	 hdr_string[val_begin]==' ';val_begin++);
  // strip parameters
  size_t val_end = hdr_string.find(';', val_begin);
  if (val_end == string::npos) 
    val_end=hdr_string.length();
  return hdr_string.substr(val_begin, val_end-val_begin);
}

string get_header_param(const string& hdr_string, 
			const string& param_name) 
{
  size_t pos = 0;
  while (pos<hdr_string.length()) {
    pos = hdr_string.find(';',pos);
    if (pos == string::npos) 
      return "";
    if ((hdr_string.length()>pos+param_name.length()+1)
	&& hdr_string.substr(++pos, param_name.length())==param_name 
	&& hdr_string[pos+param_name.length()] == '=') {
      size_t pos2 = pos+param_name.length()+1;
      while(pos2<hdr_string.length()){

	  switch(hdr_string[pos2]) {
	  case ';':
	  case '\n':
	  case '\r':
	      break;

	  default:
	      pos2++;
	      continue;
	  }

	  break;
      }
      return hdr_string.substr(pos + param_name.length() + 1, // skip 'param=' 
			       pos2 - pos - param_name.length() - 1);
    }
    pos +=param_name.length();
  }
  return "";
}

/** get the value of key @param short_name or @param name or from the list param_hdr*/
string get_header_keyvalue(const string& param_hdr, const string& short_name, const string& name) {
  string res = get_header_keyvalue(param_hdr, short_name);
  if (res.length())
    return res;

  return get_header_keyvalue(param_hdr, name);
}

/** 
 * get value from parameter header with the name @param name
 * while skipping escaped values
 */
string get_header_keyvalue(const string& param_hdr, const string& name) {
  vector <string> parts = explode(param_hdr, ",");
  vector<string>::iterator vit;
  string part;
  for ( vit=parts.begin() ; vit < parts.end(); vit++ )
  {
    part = get_header_keyvalue_single(*vit, name);
    if(!part.empty()) break;
  }
  return part;
}

string get_header_keyvalue_single(const string& param_hdr, const string& name) {
  // ugly, but we need escaping
#define ST_FINDBGN  0
#define ST_FB_ESC   1
#define ST_BEGINKEY 2
#define ST_CMPKEY   3
#define ST_FINDEQ   4
#define ST_FINDVAL  5
#define ST_VALUE    6
#define ST_VAL_ESC  7

  size_t p=0, k_begin=0, corr=0, 
    v_begin=0, v_end=0;

  char last = ' ';
  char esc_char = ' ';

  unsigned int st = ST_BEGINKEY;
  
  while (p<param_hdr.length() && !v_end) {
    char curr = param_hdr[p];
    // DBG("curr %c, st=%d, corr=%d\n", curr, st, corr);
    switch(st) {
    case ST_FINDBGN: {
      switch(curr) {
      case '"':
      case '\'':
	{
	  st = ST_FB_ESC;
	  esc_char = curr;
	} break;
      case ';':
	st = ST_BEGINKEY;
	break;
      default: break;
      } break;
    } break;

    case ST_FB_ESC: {
      if (curr == esc_char && last != '\\') {
	st = ST_FINDBGN;
      }
    } break;

    case ST_BEGINKEY: {
      switch (curr) {
      case ' ': // spaces before the key
      case '\t':
      case ';': // semicolons before the key
	break;
      default:
	if (curr==tolower(name[0]) || curr==toupper(name[0])) {
	  if (name.length() == 1)
	    st = ST_FINDEQ;
	  else
	    st = ST_CMPKEY;
	  k_begin = p;
	  corr = 1;
	} else {
	  st = ST_FINDBGN;
	}
      }
    } break;

    case ST_CMPKEY: {
	if (curr==tolower(name[corr]) || curr==toupper(name[corr])) {
	  corr++;
	  if (corr == name.length()) {
	    st = ST_FINDEQ;
	  }
	} else {
	  st = ST_FINDBGN;
	  corr=0;
	  p=k_begin; // will continue searching one after k_begin
	}
    } break;

    case ST_FINDEQ: {
      switch (curr) {
      case ' ':
      case '\t':
	break;
      case '=': 
	st = ST_FINDVAL; break;
      default: { 
	  st = ST_FINDBGN;
	  corr=0;
	  p=k_begin; // will continue searching one after k_begin
      } break;
      }
    } break;

    case ST_FINDVAL: {
      switch (curr) {
      case ' ':
      case '\t':
	break;

      case '"':
      case '\'': {
	st = ST_VAL_ESC;
	esc_char = curr;
	v_begin=p;
      } break;
      default: 
	st = ST_VALUE;
	v_begin=p;
      }
    } break;

    case ST_VALUE: {
      switch (curr) {
      case '"':
      case '\'': {
	st = ST_VAL_ESC;
	esc_char = curr;
      } break;
      case ';':
	v_end = p;
	break;
      default: break;
      }
    } break;


    case ST_VAL_ESC: {
      if (curr == esc_char && last != '\\') {
	st = ST_VALUE;
      }
    } break;
    }

    p++;
    last = curr;
  }

  if (!v_end && (st == ST_VALUE || st == ST_VAL_ESC))
    v_end = p;
  
  if (v_begin && v_end) {
    if ((v_end - v_begin > 1) &&
	(param_hdr[v_begin] == param_hdr[v_end-1]) &&
	((param_hdr[v_begin] == '\'') || (param_hdr[v_begin] == '"')))
	return param_hdr.substr(v_begin+1, v_end-v_begin-2); // whole value quoted

    return param_hdr.substr(v_begin, v_end-v_begin);
  }  else 
    return "";
}

/** get the value of key @param name from \ref PARAM_HDR header in hdrs */
string get_session_param(const string& hdrs, const string& name) {
  string iptel_app_param = getHeader(hdrs, PARAM_HDR, true);
  if (!iptel_app_param.length()) {
    //      DBG("call parameters header PARAM_HDR not found "
    // 	 "(need to configure ser's tw_append?).\n");
    return "";
  }

  return get_header_keyvalue(iptel_app_param, name);
}

void parse_app_params(const string& hdrs, map<string,string>& app_params)
{
  // TODO: use real parser with quoting and optimize
  vector<string> items = explode(getHeader(hdrs, PARAM_HDR, true), ";");
  for (vector<string>::iterator it=items.begin(); 
       it != items.end(); it++) {
    vector<string> kv = explode(*it, "=");
    if (kv.size() == 2) {
      app_params.insert(make_pair(kv[0], kv[1]));
    } else {
      if (kv.size() == 1) {
	app_params.insert(make_pair(*it, string()));
      }
    }
  }
}


// support for thread-safe pseudo-random numbers
static unsigned int _s_rand=0;
static AmMutex _s_rand_mut;

void init_random()
{
  int seed=0;
  FILE* fp_rand = fopen("/dev/urandom","r");
  if(fp_rand){
    if (fread(&seed,sizeof(int),1,fp_rand) != 1) {
      DBG("/dev/urandom could not be read, rng probably not initialized.\n");
    }
    fclose(fp_rand);
  }
  seed += getpid();
  seed += time(0);
  _s_rand = seed;
}

unsigned int get_random()
{
  _s_rand_mut.lock();
  unsigned int r = rand_r(&_s_rand);
  _s_rand_mut.unlock();
    
  return r;
}

// Explode string by a separator to a vector
// see http://stackoverflow.com/questions/236129/c-how-to-split-a-string
std::vector<string> explode(const string& s, const string& delim, 
			    const bool keep_empty) {
  vector<string> result;
  if (delim.empty()) {
    result.push_back(s);
    return result;
  }
  string::const_iterator substart = s.begin(), subend;
  while (true) {
    subend = search(substart, s.end(), delim.begin(), delim.end());
    string temp(substart, subend);
    if (keep_empty || !temp.empty()) {
      result.push_back(temp);
    }
    if (subend == s.end()) {
      break;
    }
    substart = subend + delim.size();
  }
  return result;
}



// Warning: static var is not mutexed
// Call this func only in init code.
//
void add_env_path(const char* name, const string& path)
{
  string var(path);
  char*  old_path=0;

  regex_t path_reg;

  assert(name);
  if((old_path = getenv((char*)name)) != 0) {
    if(strlen(old_path)){
	    
      if(regcomp(&path_reg,("[:|^]" + path + "[:|$]").c_str(),REG_NOSUB)){
	ERROR("could not compile regex\n");
	return;
      }
	    
      if(!regexec(&path_reg,old_path,0,0,0)) { // match
	regfree(&path_reg);
	return; // do nothing
      }
      regfree(&path_reg);
      var += ":" + string(old_path);
    }
  }

  DBG("setting %s to: '%s'\n",name,var.c_str());
#ifndef BSD_COMP
  setenv(name,var.c_str(),1);
#else
  string sol_putenv = name + string("=") + var;
  putenv(sol_putenv.c_str());
#endif
}

/** skip to the end of a string enclosed in round brackets, skipping more 
    bracketed items, too */
size_t skip_to_end_of_brackets(const string& s, size_t start) {
  size_t res = start;
  char last_c = ' ';
  int num_brackets = 0;
  while (res < s.size() &&
	 (s[res] != ')' || num_brackets || last_c == '\\')) {
    if (last_c != '\\') {
      if (s[res]==')' && num_brackets)
	num_brackets--;
      else if (s[res]=='(')
	num_brackets++;
    }
    last_c = s[res];
    res++;
  }
  return res;
}

bool read_regex_mapping(const string& fname, const char* sep,
			const char* dbg_type,
			RegexMappingVector& result) {
  std::ifstream appcfg(fname.c_str());
  if (!appcfg.good()) {
    ERROR("could not load %s file at '%s'\n",
	  dbg_type, fname.c_str());
    return false;
  } else {
    while (!appcfg.eof()) {
      string entry;
      getline (appcfg,entry);
      if (!entry.length())
	continue;
      size_t non_wsp_pos = entry.find_first_not_of(" \t");
      if (non_wsp_pos != string::npos && entry[non_wsp_pos] == '#')
	continue;

      vector<string> re_v = explode(entry, sep);
      if (re_v.size() != 2) {
	ERROR("Incorrect line '%s' in %s: expected format 'regexp%sstring'\n",
	      entry.c_str(), fname.c_str(), sep);
	return false;
      }
      regex_t app_re;
      if (regcomp(&app_re, re_v[0].c_str(), REG_EXTENDED)) {
	ERROR("compiling regex '%s' in %s.\n", 
	      re_v[0].c_str(), fname.c_str());
	return false;
      }
      DBG("adding %s '%s' => '%s'\n",
	  dbg_type, re_v[0].c_str(),re_v[1].c_str());
      result.push_back(make_pair(app_re, re_v[1]));
    }
  }
  return true;
}

void ReplaceStringInPlace(std::string& subject, const std::string& search,
                          const std::string& replace) {
  size_t pos = 0;
  while ((pos = subject.find(search, pos)) != std::string::npos) {
    subject.replace(pos, search.length(), replace);
    pos += replace.length();
  }
}

#define MAX_GROUPS 9

bool run_regex_mapping(const RegexMappingVector& mapping, const char* test_s,
                       string& result) {
  regmatch_t groups[MAX_GROUPS];
  for (RegexMappingVector::const_iterator it = mapping.begin();
       it != mapping.end(); it++) {
    if (!regexec(&it->first, test_s, MAX_GROUPS, groups, 0)) {
      result = it->second;
      string soh(1, char(1));
      ReplaceStringInPlace(result, "\\\\", soh);
      unsigned int g = 0;
      for (g = 1; g < MAX_GROUPS; g++) {
        if (groups[g].rm_so == (int)(size_t)-1) break;
        DBG("group %u: [%2u-%2u]: %.*s\n",
            g, groups[g].rm_so, groups[g].rm_eo,
            groups[g].rm_eo - groups[g].rm_so, test_s + groups[g].rm_so);
	std::string match(test_s + groups[g].rm_so,
			  groups[g].rm_eo - groups[g].rm_so);
        ReplaceStringInPlace(result, "\\" + int2str(g), match);
      }
      ReplaceStringInPlace(result, soh, "\\");
      return true;
    }
  }
  return false;
}

// These function comes basically from ser's uac module 
void cvt_hex(HASH bin, HASHHEX hex)
{
  unsigned short i;
  unsigned char j;

  for (i = 0; i<HASHLEN; i++)
    {
      j = (bin[i] >> 4) & 0xf;
      if (j <= 9)
	{
	  hex[i * 2] = (j + '0');
	} else {
	  hex[i * 2] = (j + 'a' - 10);
	}

      j = bin[i] & 0xf;

      if (j <= 9)
	{
	  hex[i * 2 + 1] = (j + '0');
	} else {
	  hex[i * 2 + 1] = (j + 'a' - 10);
	}
    };

  hex[HASHHEXLEN] = '\0';
}

/** get an MD5 hash of a string */
string calculateMD5(const string& input) {
  MD5_CTX Md5Ctx;
  HASH H;
  HASHHEX HH;

  MD5Init(&Md5Ctx);
  MD5Update(&Md5Ctx, (unsigned char*)input.c_str(), input.length());
  MD5Final(H, &Md5Ctx);
  cvt_hex(H, HH);
  return string((const char*)HH);
}

//stolen from apps/sbc/HeaderFiler.cpp
static int skip_header(const std::string& hdr, size_t start_pos,
						size_t& name_end, size_t& val_begin,
						size_t& val_end, size_t& hdr_end) {
	// adapted from sip/parse_header.cpp
	//stealed from

	name_end = val_begin = val_end = start_pos;
	hdr_end = hdr.length();

	//
	// Header states
	//
	enum {
		H_NAME=0,
		H_HCOLON,
		H_VALUE_SWS,
		H_VALUE,
	};

	int st = H_NAME;
	int saved_st = 0;


	size_t p = start_pos;
	for(;p<hdr.length() && st != ST_LF && st != ST_CRLF;p++){

	switch(st){

	case H_NAME:
		switch(hdr[p]){

		case_CR_LF;

		case HCOLON:
		st = H_VALUE_SWS;
		name_end = p;
		break;

		case SP:
		case HTAB:
		st = H_HCOLON;
		name_end = p;
		break;
		}
		break;

	case H_VALUE_SWS:
		switch(hdr[p]){

		case_CR_LF;

		case SP:
		case HTAB:
		break;

		default:
		st = H_VALUE;
		val_begin = p;
		break;

		};
		break;

	case H_VALUE:
		switch(hdr[p]){
		case_CR_LF;
		};
		if (st==ST_CR || st==ST_LF)
		val_end = p;
		break;

	case H_HCOLON:
		switch(hdr[p]){
		case HCOLON:
		st = H_VALUE_SWS;
		val_begin = p;
		break;

		case SP:
		case HTAB:
		break;

		default:
		DBG("Missing ':' after header name\n");
		return MALFORMED_SIP_MSG;
		}
		break;

		case_ST_CR(hdr[p]);

		st = saved_st;
		hdr_end = p;
		break;
	}
	}

	hdr_end = p;
	if (p==hdr.length() && st==H_VALUE) {
		val_end = p;
	}

	return 0;
}

/** remove all occurences of the given header from SIP headers string */
void inplaceHeaderErase(string &hdrs,const char *hdr)
{
	if(!hdr) return;

	string h(hdr);
	std::transform(h.begin(), h.end(), h.begin(), ::tolower);

	size_t start_pos = 0;
	while (start_pos<hdrs.length()) {
		size_t name_end, val_begin, val_end, hdr_end;

		if(0!=skip_header(hdrs, start_pos, name_end, val_begin,
						  val_end, hdr_end)) return;

		string hdr_name = hdrs.substr(start_pos, name_end-start_pos);
		std::transform(hdr_name.begin(), hdr_name.end(), hdr_name.begin(), ::tolower);

		if(h==hdr_name){
			hdrs.erase(start_pos, hdr_end-start_pos);
		} else {
			start_pos = hdr_end;
		}
	}
}

void inplaceHeadersErase(string &hdrs,const char *hdrv[])
{
	if(!hdrv || !*hdrv) return;

	vector<string> hs;
	while(*hdrv){
		string h(*hdrv);
		std::transform(h.begin(), h.end(), h.begin(), ::tolower);
		hs.push_back(h);
		hdrv++;
	}

	size_t start_pos = 0;
	while (start_pos<hdrs.length()) {
		size_t name_end, val_begin, val_end, hdr_end;

		if(0!=skip_header(hdrs, start_pos, name_end, val_begin,
						  val_end, hdr_end)) return;

		string hdr_name = hdrs.substr(start_pos, name_end-start_pos);
		std::transform(hdr_name.begin(), hdr_name.end(), hdr_name.begin(), ::tolower);

		vector<string>::iterator i = std::find(hs.begin(),hs.end(),hdr_name);
		if(i != hs.end()){
			hdrs.erase(start_pos, hdr_end-start_pos);
		} else {
			start_pos = hdr_end;
		}
	}
}

/*
  http://www.unicode.org/versions/Unicode7.0.0/UnicodeStandard-7.0.pdf
  page 124, 3.9 "Unicode Encoding Forms", "UTF-8"


  Table 3-7. Well-Formed UTF-8 Byte Sequences
  -----------------------------------------------------------------------------
  |  Code Points        | First Byte | Second Byte | Third Byte | Fourth Byte |
  |  U+0000..U+007F     |     00..7F |             |            |             |
  |  U+0080..U+07FF     |     C2..DF |      80..BF |            |             |
  |  U+0800..U+0FFF     |         E0 |      A0..BF |     80..BF |             |
  |  U+1000..U+CFFF     |     E1..EC |      80..BF |     80..BF |             |
  |  U+D000..U+D7FF     |         ED |      80..9F |     80..BF |             |
  |  U+E000..U+FFFF     |     EE..EF |      80..BF |     80..BF |             |
  |  U+10000..U+3FFFF   |         F0 |      90..BF |     80..BF |      80..BF |
  |  U+40000..U+FFFFF   |     F1..F3 |      80..BF |     80..BF |      80..BF |
  |  U+100000..U+10FFFF |         F4 |      80..8F |     80..BF |      80..BF |
  -----------------------------------------------------------------------------
*/
bool is_valid_utf8(std::string &s)
{
	enum state {
		ST_COMPLETED = 0,

		ST_C2DF_80BF_2nd,

		ST_E0_A0BF_80BF_2nd,
		ST_E0_A0BF_80BF_3rd,

		ST_E1EC_80BF_80BF_2nd,
		ST_E1EC_80BF_80BF_3rd,

		ST_ED_809F_80BF_2nd,
		ST_ED_809F_80BF_3rd,

		ST_EEEF_80BF_80BF_2nd,
		ST_EEEF_80BF_80BF_3rd,

		ST_F0_90BF_80BF_80BF_2nd,
		ST_F0_90BF_80BF_80BF_3rd,
		ST_F0_90BF_80BF_80BF_4th,

		ST_F1F3_80BF_80BF_80BF_2nd,
		ST_F1F3_80BF_80BF_80BF_3rd,
		ST_F1F3_80BF_80BF_80BF_4th,

		ST_F4_808F_80BF_80BF_2nd,
		ST_F4_808F_80BF_80BF_3rd,
		ST_F4_808F_80BF_80BF_4th
	} st = ST_COMPLETED;

	static const struct {
		unsigned char start;
		unsigned char end;
		state next_state;
	} state2transition[] = {
		{ 0x00, 0x00, ST_COMPLETED },

		{ 0x80, 0xBF, ST_COMPLETED },

		{ 0xA0, 0XBF, ST_E0_A0BF_80BF_3rd },
		{ 0x80, 0xBF, ST_COMPLETED },

		{ 0x80, 0xBF, ST_E1EC_80BF_80BF_3rd },
		{ 0x80, 0xBF, ST_COMPLETED },

		{ 0x80, 0x9F, ST_ED_809F_80BF_3rd },
		{ 0x80, 0xBF, ST_COMPLETED },

		{ 0x80, 0xBF, ST_EEEF_80BF_80BF_3rd },
		{ 0x80, 0xBF, ST_COMPLETED },

		{ 0x90, 0xBF, ST_F0_90BF_80BF_80BF_3rd },
		{ 0x80, 0xBF, ST_F0_90BF_80BF_80BF_4th },
		{ 0x80, 0xBF, ST_COMPLETED },

		{ 0x80, 0xBF, ST_F1F3_80BF_80BF_80BF_3rd },
		{ 0x80, 0xBF, ST_F1F3_80BF_80BF_80BF_4th },
		{ 0x80, 0xBF, ST_COMPLETED },

		{ 0x80, 0x8F, ST_F4_808F_80BF_80BF_3rd },
		{ 0x80, 0xBF, ST_F4_808F_80BF_80BF_4th },
		{ 0x80, 0xBF, ST_COMPLETED },
	};
	(void)state2transition;

	static const char *state2checked_bytes_sequence[] = {
		"",
		"C2..DF",
		"E0", "E0_A0..BF",
		"E1..EC", "E1..EC_80..BF",
		"ED", "ED_80..9F",
		"EE..EF", "EE..EF_80..BF",
		"F0","FO_90..BF","FO_90..BF_80..BF",
		"F1..F3","F1..F3_80..BF","F1..F3_80..BF_80..BF",
		"F4","F4_80..8F","F4_80..8F_80..BF",
	};
	(void)state2checked_bytes_sequence;

	/*static const int state2byte_num[] = {
		0,
		2,
		2, 3,
		2, 3,
		2, 3,
		2, 3,
		2, 3, 4,
		2, 3, 4,
		2, 3, 4
	};
	(void)state2byte_num;*/

#define VALIDATE_RANGE(condition_state) \
	case condition_state: \
		if(IS_IN(c, \
			state2transition[condition_state].start, \
			state2transition[condition_state].end)) \
		{ \
			st = state2transition[condition_state].next_state; \
			break; \
		} else { \
			DBG("is_valid_utf8(): unexpected byte %02X after %s bytes. " \
				"expected to be within %02X..%02X", \
				c,state2checked_bytes_sequence[st], \
				state2transition[condition_state].start, \
				state2transition[condition_state].end); \
			return false; \
		}

	for(const unsigned char &c: s) {
		switch(st) {

		case ST_COMPLETED:
			if(IS_IN(c,0x00,0x7F)) //*00..7F
				continue;

			switch(c) {
			case 0xE0: //*E0, A0..BF, 80..BF
				st = ST_E0_A0BF_80BF_2nd;
				continue;
			case 0xED: //*ED, 80..9F, 80..BF
				st = ST_ED_809F_80BF_2nd;
				continue;
			case 0xF0: //*F0, 90..BF, 80..BF, 80..BF
				st = ST_F0_90BF_80BF_80BF_2nd;
				continue;
			case 0xF4: //*F4, 80..8F, 80..BF, 80..BF
				st = ST_F4_808F_80BF_80BF_2nd;
				continue;
			default:
				if(IS_IN(c,0xC2,0xDF)) { //*C2..DF, 80..BF
					st = ST_C2DF_80BF_2nd;
					continue;
				}
				if(IS_IN(c,0xE1,0xEC)) { //*E1..EC, 80..BF, 80..BF
					st = ST_E1EC_80BF_80BF_2nd;
					continue;
				}
				if(IS_IN(c,0xEE,0xEF)) { //*EE..EF, 80..BF, 80..BF
					st = ST_EEEF_80BF_80BF_3rd;
					continue;
				}
				if(IS_IN(c,0xF1,0xF3)) { //*F1..F3, 80..BF, 80..BF, 80..BF
					st = ST_F1F3_80BF_80BF_80BF_4th;
					continue;
				}
			} //switch(c)

			DBG("is_valid_utf8(): unexpected sequence first byte %02X",c);
			return false;

		//C2..DF, 80..BF
		VALIDATE_RANGE(ST_C2DF_80BF_2nd);

		//E0, A0..BF, 80..BF
		VALIDATE_RANGE(ST_E0_A0BF_80BF_2nd);
		VALIDATE_RANGE(ST_E0_A0BF_80BF_3rd);

		//E1..EC, 80..BF, 80..BF
		VALIDATE_RANGE(ST_E1EC_80BF_80BF_2nd);
		VALIDATE_RANGE(ST_E1EC_80BF_80BF_3rd);

		//ED, 80..9F, 80..BF
		VALIDATE_RANGE(ST_ED_809F_80BF_2nd);
		VALIDATE_RANGE(ST_ED_809F_80BF_3rd);

		//EE..EF, 80..BF, 80..BF
		VALIDATE_RANGE(ST_EEEF_80BF_80BF_2nd);
		VALIDATE_RANGE(ST_EEEF_80BF_80BF_3rd);

		//F0, 90..BF, 80..BF, 80..BF
		VALIDATE_RANGE(ST_F0_90BF_80BF_80BF_2nd);
		VALIDATE_RANGE(ST_F0_90BF_80BF_80BF_3rd);
		VALIDATE_RANGE(ST_F0_90BF_80BF_80BF_4th);

		//F1..F3, 80..BF, 80..BF, 80..BF
		VALIDATE_RANGE(ST_F1F3_80BF_80BF_80BF_2nd);
		VALIDATE_RANGE(ST_F1F3_80BF_80BF_80BF_3rd);
		VALIDATE_RANGE(ST_F1F3_80BF_80BF_80BF_4th);

		//F4, 80..8F, 80..BF, 80..BF
		VALIDATE_RANGE(ST_F4_808F_80BF_80BF_2nd);
		VALIDATE_RANGE(ST_F4_808F_80BF_80BF_3rd);
		VALIDATE_RANGE(ST_F4_808F_80BF_80BF_4th);
		default:
			DBG("is_valid_utf8(): unknown state: %d",st);
			return false;
		} //switch(st)
	}

	if(st!=ST_COMPLETED) {
		DBG("is_valid_utf8(): uncompleted utf8 multibyte sequence. st: %d",st);
		return false;
	}

	return true;
#undef VALIDATE_RANGE
}
