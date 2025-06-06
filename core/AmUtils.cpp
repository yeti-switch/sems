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
#include "netlink.h"
#include "log.h"
#include "AmSipMsg.h"
#include "sip/resolver.h"
#include "sip/ip_util.h"
#include "sip/parse_uri.h"
#include "sip/parse_common.h"
#include "sip/resolver.h"

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


static char _int2str_lookup[] = { '0', '1', '2', '3', '4', '5', '6' , '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };

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

template<class T, class DT, int scale>
string signed2str(T val, T (*abs_func) (T), DT (*div_func) (T, T))
{
  char buffer[64] = {0,0};
  int i=62;
  DT d;

  d.quot = abs_func(val);
  do{
    d = div_func(d.quot,scale);
    buffer[i] = _int2str_lookup[d.rem];
  }while(--i && d.quot);

  if (i && (val<0)) {
    buffer[i]='-';
    i--;
  }

  return string((char*)(buffer+i+1));
}

string int2hexstr(int val) { return signed2str<int, div_t, 16>(val, abs, div); }
string int2str(int val) { return signed2str<int, div_t, 10>(val, abs, div); }
string long2str(long int val) { return signed2str<long, ldiv_t, 10>(val, labs, ldiv); }
string longlong2str(long long int val) { return signed2str<long long, lldiv_t, 10>(val, llabs, lldiv); }

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

string long2hex(unsigned long val, bool lowercase)
{
  unsigned int digit=0;

  char buffer[2*sizeof(long)+1] = {0};
  int i,j=0;

  for(i=0; i<int(2*sizeof(long)); i++){
    digit = val >> 4*(2*sizeof(long)-1);
    val = val << 4;
    buffer[j++] = lowercase ? _int2hex_lookup_l[(unsigned char)digit] : _int2hex_lookup[(unsigned char)digit];
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

bool hex2int(const string& str, unsigned int& result)
{
    unsigned int ret = 0,
                 i = 0;

    for(const auto &c: str) {
        if(++i > 8 /* unsigned int countains up to 4 bytes (8 nablas)*/) {
            DBG("hex2int: too many digits in %s", str.data());
            return true;
        }
        ret <<= 4;
        if(c =='0')
            continue;
        if (c > '0' && c <= '9')
            ret += static_cast<unsigned int>(c - '0');
        else if(c >= 'a' && c <= 'f')
            ret += static_cast<unsigned int>(c -'a' + 10);
        else if(c >= 'A' && c <= 'F')
            ret += static_cast<unsigned int>(c -'A' + 10);
        else {
            DBG("hex2int: unexpected char 0x%x in %s", c, str.data());
            return true;
        }
    }

    result = ret;
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
  DBG("str2i: too many letters in [%s]", init);
  return true;
 error_char:
  DBG("str2i: unexpected char 0x%x in %s", *str, init);
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
  DBG("str2int: too many digits in [%s]", init);
  return false;
 error_char:
  DBG("str2i: unexpected char 0x%x in %s", *str, init);
  return false;
}

bool str2int(const char* str, int len, int& result, char sep)
{
  int ret=0;
  int i=0;
  const char* init = str;
  const char* end = init + len;
  int sign = 1;

  for (; str != end && *str == ' '; ++str);

  if (*str == '-') {
    sign = -1;
    str++;

    for(; str != end && *str == ' '; ++str);
  }

  if (str == end)
    goto error_no_digits;

  for (; str != end; ++str) {
    if (*str <= '9' && *str >= '0') {
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

      if((*str != sep) && !eol)
        goto error_char;

      break;
    }
  }

  result = ret * sign;
  return true;

  error_no_digits:
  DBG("no digits");
  return false;

  error_digits:
  DBG("str2int: too many digits in [%s]", init);
  return false;

  error_char:
  DBG("str2i: unexpected char 0x%x in %s", *str, init);
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
  DBG("str2long: too many digits in [%s]", init);
  return false;
 error_char:
  DBG("str2long: unexpected char 0x%x in %s", *str, init);
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

std::optional<bool> str2bool(const string &s) {
  bool ret;
  if(str2bool(s, ret)) {
    return ret;
  }
  return std::nullopt;
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
  DBG("str2long: too many digits in [%s]", init);
  return false;
 error_char:
  DBG("str2long: unexpected char 0x%x in %s", *str, init);
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
	DBG("error in escaped string: %%%c%c", s[pos-1], s[pos]);
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
	DBG("error in escaped string: %%%c%c", s[pos-1], s[pos]);
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

std::optional<std::pair<string, uint16_t>> parse_hostport(const std::string & host_port, bool allow_fqdn)
{
    std::pair<string, uint16_t> ret;
    auto &[host, port] = ret;

    if(host_port.empty()) {
        ERROR("empty host:port string");
        return std::nullopt;
    }

    enum state {
        host_part_start,
        host_part_fqdn,
        host_part_ipv4,
        host_part_ipv6_reference,
        host_port_delimiter,
        port_part,
    } st = host_part_start;

    port = 0;

    string::size_type host_start_pos = 0;
    string::size_type port_start_pos = 0;
    string::size_type pos = 0;

    bool ipv6 = false, ipv4 = false;

    for(auto const &c : host_port) {
        switch(st) {
        case host_part_start:
            switch(c) {
            case '[':
                st = host_part_ipv6_reference;
                ipv6 = true;
                host_start_pos++;
                break;
            case '.':
            case '0'...'9':
                ipv4 = true;
                st = host_part_ipv4;
                break;
            case 'a'...'z':
            case 'A'...'Z':
                if(!allow_fqdn) {
                    ERROR("fqdn is not allowed for host_port string '%s'",
                        host_port.data());
                    return std::nullopt;
                }
                st = host_part_fqdn;
                break;
            default:
                ERROR("unexpected starting char '%c' in host_port string '%s'",
                    c, host_port.data());
                return std::nullopt;
            }
            break;
        case host_part_fqdn:
            switch(c) {
            case '.':
            case '-':
            case '0'...'9':
            case 'a'...'z':
            case 'A'...'Z':
                break;
            case ':':
                host = host_port.substr(host_start_pos, pos - host_start_pos);
                port_start_pos = pos + 1;
                st = port_part;
                break;
            default:
                ERROR("unexpected fqdn char '%c' in host_port string '%s'",
                    c, host_port.data());
                return std::nullopt;
            }
            break;
        case host_part_ipv4:
            switch(c) {
            case '.':
            case '0'...'9':
                break;
            case ':':
                host = host_port.substr(host_start_pos, pos - host_start_pos);
                port_start_pos = pos + 1;
                st = port_part;
                break;
            default:
                ERROR("unexpected ipv4 address char '%c' in host_port string '%s'",
                    c, host_port.data());
                return std::nullopt;
            }
            break;
        case host_part_ipv6_reference:
            switch(c) {
            case ':':
            case '0'...'9':
            case 'a'...'f':
            case 'A'...'F':
                break;
            case ']':
                host = host_port.substr(host_start_pos, pos - host_start_pos);
                st = host_port_delimiter;
                break;
            default:
                ERROR("unexpected ipv6 address char '%c' in host_port string '%s'",
                    c, host_port.data());
                return std::nullopt;
            }
            break;
        case host_port_delimiter:
            if(c != ':') {
                ERROR("unexpected char '%c' after the ipv6 reference in host_port string '%s'",
                    c, host_port.data());
                return std::nullopt;
            }
            port_start_pos = pos + 1;
            st = port_part;
            break;
        case port_part:
            switch(c) {
            case '0'...'9':
                port = port*10 + c-'0';
                break;
            default:
                ERROR("unexpected char '%c' for port in host_port string '%s'",
                    c, host_port.data());
                return std::nullopt;
            }
            break;
        }

        pos++;
    }

    if (st != port_part || port_start_pos == host_port.length()) {
        ERROR("empty port for host_port string '%s'", host_port.data());
        return std::nullopt;
    }

    if (std::to_string(port) != host_port.substr(port_start_pos, host_port.length())) {
        ERROR("port value overflow for host_port string '%s'", host_port.data());
        return std::nullopt;
    }

    if(ipv4 && 1!=validate_ipv4_addr(host)) {
        ERROR("incorrect IPv4 address '%s' for host_port string '%s'",
            host.data(), host_port.data());
        return std::nullopt;
    }

    if(ipv6 && 1!=validate_ipv6_addr(host)) {
        ERROR("incorrect IPv6 address '%s' for host_port string '%s'",
            host.data(), host_port.data());
        return std::nullopt;
    }

    return ret;
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
    ERROR("expected 0x%x or 0x%x or 0x%x, found 0x%x",' ','\t','-',*cur);
    goto error;
  }

  if(sscanf(res_code_str,"%u",&res_code) != 1){
    ERROR("wrong code (%s)",res_code_str);
    goto error;
  }

  // wrap spaces and tabs
  while( (*cur == ' ') || (*cur == '\t') || (*cur =='-')) 
    cur++;

  res_msg = cur;
  return 0;

 error:
  ERROR("while parsing response");
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
  return path;
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
    NetlinkHelper& helper = NetlinkHelper::instance();
    if(!helper.get_local_addr(*remote_ip, *local))
        return -1;
    return 0;
}

int validate_ipv4_addr(const string& ip)
{
    sockaddr_storage addr;
    return inet_pton(AF_INET, ip.c_str(), &((sockaddr_in*)&addr)->sin_addr);
}

int validate_ipv6_addr(const string& ip)
{
    sockaddr_storage addr;
    return inet_pton(AF_INET6, ip.c_str(), &((sockaddr_in6*)&addr)->sin6_addr);
}

int get_local_addr_for_dest(const string& remote_ip, string& local, dns_priority priority)
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
    err = resolver::instance()->resolve_name(remote_ip.c_str(),&dh,&remote_ip_ss,priority);
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

int get_local_addr_for_dest(const struct sip_uri &remote_uri, string& local, dns_priority priority)
{
    sockaddr_storage remote_ip_ss;
    sockaddr_storage local_ss;
    int err = resolve_sip_uri(remote_uri, remote_ip_ss, priority);
    if(err == -1) {
        ERROR("While converting uri with host: '%s'", c2stlstr(remote_uri.host).c_str());
        return -1;
    }

    err = get_local_addr_for_dest(&remote_ip_ss, &local_ss);
    if(err < 0) {
        return -1;
    }

    char tmp_addr[NI_MAXHOST];
    if(am_inet_ntop(&local_ss,tmp_addr,NI_MAXHOST) != NULL) {
        local = tmp_addr;
        return 0;
    }

    return -1;
}


int resolve_sip_uri(const struct sip_uri &uri, string& addr, dns_priority priority)
{
    sockaddr_storage ip_ss;
    int err = resolve_sip_uri(uri, ip_ss, priority);
    if(err == -1) {
        return -1;
    }

    char tmp_addr[NI_MAXHOST];
    if(am_inet_ntop(&ip_ss,tmp_addr,NI_MAXHOST) != NULL) {
        addr = tmp_addr;
        return 0;
    }

    return -1;
}

int resolve_sip_uri(const struct sip_uri &uri, sockaddr_storage& addr, dns_priority priority)
{
    sip_target_set targets(priority);
    static cstring sip_scheme("sip");
    static cstring sips_scheme("sips");
    static cstring udp_transport("udp");

    int err = 0;
    if(uri.host.len < INET6_ADDRSTRLEN) {
        char host[INET6_ADDRSTRLEN] = {0};
        strncpy(host, uri.host.s, uri.host.len);
        int err = inet_pton(AF_INET,host,&((sockaddr_in*)&addr)->sin_addr);
        if(err == 1) {
            addr.ss_family = AF_INET;
        } else if(err == 0) {
            err = inet_pton(AF_INET6,host,&((sockaddr_in6*)&addr)->sin6_addr);
            if(err == 1) {
                addr.ss_family = AF_INET6;
            }
        }
    }

    if(err == 0) {
        list<sip_destination> dest_list;
        dest_list.resize(1);
        sip_destination &dest = dest_list.back();

        dest.host = uri.host;
        dest.port = uri.port;

        if(uri.scheme != sip_uri::SIPS) {
            dest.scheme = sip_scheme;
        } else {
            dest.scheme = sips_scheme;
        }

        if(uri.trsp) {
            dest.trsp = uri.trsp->value;
        } else {
            dest.trsp = udp_transport;
        }

        err = resolver::instance()->resolve_targets(dest_list, &targets);

        if(targets.dest_list.empty()) {
            DBG("no resolved targets for host: '%s'", c2stlstr(uri.host).c_str());
            return -1;
        }
        memcpy(&addr, &targets.dest_list.begin()->ss, sizeof(addr));
        //DBG("addr: %s",get_addr_str(&addr).c_str());
    }

    if(err == -1) {
        DBG("failed to convert uri with host: '%s'", c2stlstr(uri.host).c_str());
        return -1;
    }

    if(addr.ss_family==AF_INET) {
#if defined(BSD44SOCKETS)
        ((sockaddr_in*)&addr)->sin_len = sizeof(sockaddr_in);
#endif
        ((sockaddr_in*)&addr)->sin_port = htons(5060); // fake port number
    } else {
#if defined(BSD44SOCKETS)
        ((sockaddr_in6*)&addr)->sin6_len = sizeof(sockaddr_in6);
#endif
        ((sockaddr_in6*)&addr)->sin6_port = htons(5060); // fake port number
    }

    return 0;
}

void ensure_ipv6_reference(std::string &s)
{
    sockaddr_in6 addr;
    if(s.size() > 2 &&
       s[0] != '[' &&
       1 == inet_pton(AF_INET6, s.c_str(), &addr))
    {
        s.insert(0,"[");
        s.append("]");
    }
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
    // DBG("curr %c, st=%d, corr=%d", curr, st, corr);
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
      DBG("/dev/urandom could not be read, rng probably not initialized.");
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
	ERROR("could not compile regex");
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

  DBG("setting %s to: '%s'",name,var.c_str());
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
    ERROR("could not load %s file at '%s'",
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
	ERROR("Incorrect line '%s' in %s: expected format 'regexp%sstring'",
	      entry.c_str(), fname.c_str(), sep);
	return false;
      }
      regex_t app_re;
      if (regcomp(&app_re, re_v[0].c_str(), REG_EXTENDED)) {
	ERROR("compiling regex '%s' in %s.", 
	      re_v[0].c_str(), fname.c_str());
	return false;
      }
      DBG("adding %s '%s' => '%s'",
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
        DBG("group %u: [%2u-%2u]: %.*s",
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
int skip_header(const std::string& hdr, size_t start_pos,
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
		DBG("Missing ':' after header name");
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


int strncmp2(const char* str1, size_t len1, const char* str2, size_t len2) {
	return len1 == len2 ? strncmp(str1, str2, len1) : len1 > len2;
}
