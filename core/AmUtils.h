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

#ifndef _AmUtils_h_
#define _AmUtils_h_

#include <stdio.h>
#include <sys/stat.h>
#include <errno.h>
#include <sys/types.h>
#include <regex.h>
#include <sys/socket.h>
#include <sys/time.h>

#include <string>
using std::string;

#include <vector>
#include <utility>
#include <map>
#include <optional>

#include "md5.h"
#include "sip/resolver.h"

#define HASHLEN 16
typedef unsigned char HASH[HASHLEN];

#define HASHHEXLEN 32
typedef unsigned char HASHHEX[HASHHEXLEN+1];

//#define FIFO_PERM S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH|S_IWOTH

#define PARAM_HDR "P-App-Param"
#define APPNAME_HDR "P-App-Name"

/** @file AmUtils.h */

/**
 * update min max values (min/max should be initialized with 0 before usage)
 */
void update_min_max(double &min, double &max, double v);
/**
 * Convert an timeval to a string. (uses just tv_sec part of timeval struct)
 */
string timeval2str(const timeval &tv);

/**
 * Convert an timeval to a string. (seconds as integral part, useconds as fractional)
 */
string timeval2str_usec(const timeval &tv);

/**
 * Convert an timeval to a string.
 * NTP format: hh:mm:ss.mmm ZON DDD MMM ## YYYY
 */
string timeval2str_ntp(const timeval &tv);

/**
 * Convert an timeval to a double (tv_sec as integral and tv_usec as fractional part)
 */
double timeval2double(const timeval &tv);

/** 
 * Convert an int to a string. 
 */
string int2str(int val);

/**
 * Convert an unsigned int to a string.
 */
string int2str(unsigned int val);

/** 
 * Convert a long to a string. 
 */
string long2str(long int val);

/** 
 * Convert a long long to a string. 
 */
string longlong2str(long long int val);

/**
  * Convert longlong milliseconds to timespec
  */
void longlong2timespec(struct timespec &ts,unsigned long long msec);

/** 
 * Convert a a byte to a string using hexdecimal representation.
 */
string char2hex(unsigned char val, bool lowercase = false);

/**
 * Convert an unsigned int to a string using hexdecimal representation. 
 */
string int2hex(unsigned int val, bool lowercase = false);

/**
 * Convert an int to a string using hexdecimal representation.
 */
string int2hexstr(int val);

/** 
 * Convert an unsigned long to a string using hexdecimal representation. 
 */
string long2hex(unsigned long val, bool lowercase = false);

/**
 * Convert a reversed hex string to uint.
 * @param str    [in]  string to convert.
 * @param result [out] result integer.
 * @return true if failed. 
 */
bool reverse_hex2int(const string& str, unsigned int& result);

/**
 * Convert a hex string to uint.
 * @param str    [in]  string to convert.
 * @param result [out] result integer.
 * @return true if failed.
 */
bool hex2int(const string& str, unsigned int& result);

/** 
 * Convert a double to a string. 
 */
string double2str(double val);

/** 
 * Convert a string to an uint. 
 * @param str    [in]  string to convert.
 * @param result [out] result integer.
 * @return true if failed (!!!)
 */
bool str2i(const string& str, unsigned int& result);

/** 
 * Internal version of preceeding 'str2i' method. 
 * @param str    [in,out] gets incremented until sep char or error occurs
 * @param result [out] result of the function
 * @param sep    [in] character seprating the number to convert and the next token
 * @return true if failed (!!!)
 */
bool str2i(char*& str, unsigned int& result, char sep = ' ');


/** 
 * Convert a string to an int. 
 * @param str    [in]  string to convert.
 * @param result [out] result integer.
 * @return true on success (!!!)
 */
bool str2int(const string& str, int& result);

/** 
 * Internal version of preceeding 'str2int' method. 
 * @param str    [in,out] gets incremented until sep char or error occurs
 * @param result [out] result of the function
 * @param sep    [in] character seprating the number to convert and the next token
 * @return true on success (!!!)
 */
bool str2int(char*& str, int& result, char sep = ' ');

/**
 * Convert a lengthed string to an int
 * @param str    [in] string to convert
 * @param len    [in] length of string
 * @param result [out] result of the function
 * @param sep    [in] character seprating the number to convert and the next token
 * @return true on success (!!!)
 */
bool str2int(const char* str, int len, int& result, char sep = ' ');

/** 
 * Convert a string to a long int. 
 * On many systems nowadays this could be the same as str2int.
 * @param str    [in]  string to convert.
 * @param result [out] result integer.
 * @return true if on success (!!!).
 */
bool str2long(const string& str, long& result);

/** 
 * Internal version of preceeding 'str2long' method. 
 * @param str    [in,out] gets incremented until sep char or error occurs
 * @param result [out] result of the function
 * @param sep    [in] character seprating the number to convert and the next token
 * @return true on success
 */
bool str2long(char*& str, long& result, char sep = ' ');

/**
 * Convert a string to a long long int.
 * On many systems nowadays this could be the same as str2int.
 * @param str    [in]  string to convert.
 * @param result [out] result integer.
 * @return true if on success (!!!).
 */
bool str2longlong(const string& str, long long& result);

/**
 * Internal version of preceeding 'str2longlong' method.
 * @param str    [in,out] gets incremented until sep char or error occurs
 * @param result [out] result of the function
 * @param sep    [in] character seprating the number to convert and the next token
 * @return true on success
 */
bool str2longlong(char*& str, long long& result, char sep = ' ');

/* translates string value into bool, returns false on error */
bool str2bool(const string &s, bool &dst);

/* translates string value into bool, returns std::nullopt on error */
std::optional<bool> str2bool(const string &s);

std::string URL_decode(const std::string& s);
std::string URL_encode(const std::string& s);

/**
 * @brief Parse/validate string with 'host:port' format
 * @param[in] host_port     string to parse
 * @param[in] allow_fqdn    whether to allow domain names. default:false
 * @return std::pair with parsed host and port values
 */
std::optional<std::pair<string, uint16_t>> parse_hostport(const std::string & host_port, bool allow_fqdn = false);

/**
 * Parse code/reason line.
 * Syntax: "code reason"
 *
 * @param lbuf line     buffer to parse.
 * @param res_code_str  char[4]; Syntax: xxxx whereby 
 *                      each x is a between 0 and 9.
 * @param res_code      where to store the resulting integer 'code'.
 * @param res_msg       where to store the 'reason'.
 */
int parse_return_code(const char* lbuf, 
		      unsigned int& res_code, string& res_msg );
/**
 * Tells if a file exists.
 * @param name file name.
 * @return true if file could be openned.
 */
bool file_exists(const string& name);

/**
 * @return A file name extracted from the given full path file name.
 */
string filename_from_fullpath(const string& path);

/**
 * @return A file extension extracted from the given full path file name.
 */
string file_extension(const string& path);

/**
 * @return new path resulting from the concatanation of path, 
 * suffix and eventually a slash between them
 */
string add2path(const string& path, int n_suffix, ...);

string get_addr_str(const sockaddr_storage* addr);
string get_addr_str_sip(const sockaddr_storage* addr);

/** \brief microseconds sleep using select */
#define sleep_us(nusecs) \
	{ \
	struct timeval tval; \
	tval.tv_sec=nusecs/1000000; \
	tval.tv_usec=nusecs%1000000; \
	select(0, NULL, NULL, NULL, &tval ); \
	}

int resolve_sip_uri(const struct sip_uri &uri, string& addr, dns_priority priority);
int resolve_sip_uri(const struct sip_uri &uri, sockaddr_storage& addr, dns_priority priority);

int validate_ipv4_addr(const string& ip);
int validate_ipv6_addr(const string& ip);

/* Computes the local address for a specific destination address.
 * This is done using Netlink RTM_F_LOOKUP_TABLE request
 */
int get_local_addr_for_dest(sockaddr_storage* remote_ip, sockaddr_storage* local);
int get_local_addr_for_dest(const string& remote_ip, string& local, dns_priority priority);
int get_local_addr_for_dest(const struct sip_uri &remote_uri, string& local, dns_priority priority);


void ensure_ipv6_reference(std::string &s);

string extract_tag(const string& addr);

/** returns true if key is in s_list, a list of items delimited by list_delim
 *skips whitespaces, too */
bool key_in_list(const string& s_list, const string& key, char list_delim = ',');

/** return string with trailing spaces and everything after ; including ; itself removed */
string strip_header_params(const string& hdr_string);

/** get a header parameter value */
string get_header_param(const string& hdr_string, const string& param_name);

/** get the value of key @param name from the list param_hdr*/
string get_header_keyvalue(const string& param_hdr, const string& name);

/** get the value of key @param name from the list param_hdr, no comma separated values*/
string get_header_keyvalue_single(const string& param_hdr, const string& name);

/** get the value of key @param short_name or @param name or from the list param_hdr*/
string get_header_keyvalue(const string& param_hdr, const string& short_name, const string& name);

/** get the value of key @param name from P-Iptel-Param header in hdrs */
string get_session_param(const string& hdrs, const string& name);

/** parse the P-App-Param header and extracts the parameters into a map */
void parse_app_params(const string& hdrs, std::map<string,string>& app_params);

/** support for thread-safe pseudo-random numbers  - init function */
void init_random();
/** support for thread-safe pseudo-random numbers  - make a random number function */
unsigned int get_random();

/** Explode string by a separator to a vector */
std::vector<string> explode(const string& s, const string& delim, const bool keep_empty = false);

/** remove chars in sepSet from beginning and end of str */
inline std::string trim(std::string const& str,char const* sepSet)
{
  std::string::size_type const first = str.find_first_not_of(sepSet);
  return ( first==std::string::npos ) ?
    std::string() : str.substr(first, str.find_last_not_of(sepSet)-first+1);
}

/** add a directory to an environement variable */
void add_env_path(const char* name, const string& path);


size_t skip_to_end_of_brackets(const string& s, size_t start);

typedef std::vector<std::pair<regex_t, string> > RegexMappingVector;

/** read a regex=>string mapping from file
    @return true on success
 */
bool read_regex_mapping(const string& fname, const char* sep,
			const char* dbg_type,
			RegexMappingVector& result);

/** run a regex mapping - result is the first matching entry 
    @return true if matched
 */
bool run_regex_mapping(const RegexMappingVector& mapping, const char* test_s,
		       string& result);


/** convert a binary MD5 hash to hex representation */
void cvt_hex(HASH bin, HASHHEX hex);

/** get an MD5 hash of a string */
string calculateMD5(const string& input);

/** remove all occurences of the given header from SIP headers string */
void inplaceHeaderErase(string &hdrs,const char *hdr);

/** remove all occurences of the given headers from SIP headers string */
void inplaceHeadersErase(string &hdrs,const char *hdrv[]);

/** helper function for inplaceHeadersErase func */
int skip_header(const std::string& hdr, size_t start_pos,
                size_t& name_end, size_t& val_begin,
                size_t& val_end, size_t& hdr_end);

bool is_valid_utf8(const std::string &s);
bool fixup_utf8_inplace(std::string &s);

/** augmented strncmp function which also compares string lengths */
int strncmp2(const char* str1, size_t len1, const char* str2, size_t len2);

#endif

// Local Variables:
// mode:C++
// End:
