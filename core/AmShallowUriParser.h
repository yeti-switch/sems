#pragma once

#include <string>
#include <string_view>
#include <list>
#include <map>
#include <cstdint>

#include "sip/parse_uri.h"
#include "sip/parse_nameaddr.h"
#include "sip/parse_via.h"

using std::map;
using std::string;
using std::string_view;

// wrapper around parsers from sip/parse_uri.h, sip/parse_nameaddr.h

class AmShallowUriParser {
  public:
    using kv_container = map<string_view, string_view>;

  private:
    string_view         display_name;
    string_view         uri_user;
    string_view         uri_host;
    uint16_t            uri_port = 0;
    sip_uri::uri_scheme uri_scheme;

    kv_container uri_headers;
    kv_container uri_params;
    kv_container header_params;

    // storage for mutated data
    std::list<string> storage_;

    string_view own(const string_view &val);
    void        own_map(kv_container &m);
    void        set_map_param(kv_container &m, const string_view &name, const string_view &value);

    void append_with_canon_uri_str(string &res) const;
    void append_with_uri_str(string &res) const;

  public:
    // modify/parse functions
    void clear();
    void apply_uri(const sip_uri &parsed_sip_uri);
    void apply_nameaddr(const sip_nameaddr &sip_nameaddr);
    bool parse_uri(const string_view &input);
    bool parse_nameaddr(const string_view &input);

    // copy all references into storage_
    void convert_to_deep_copy();

    // serialization functions
    string uri_str() const;
    string canon_uri_str() const;
    string nameaddr_str() const;
    string print() const; // alias for nameaddr_str()

    // getters
    const string_view  &get_display_name() const { return display_name; }
    const string_view  &get_uri_user() const { return uri_user; }
    const string_view  &get_uri_host() const { return uri_host; }
    uint16_t            get_uri_port() const { return uri_port; }
    sip_uri::uri_scheme get_uri_scheme() const { return uri_scheme; }
    const kv_container &get_uri_headers() const { return uri_headers; }
    const kv_container &get_uri_params() const { return uri_params; }
    const kv_container &get_header_params() const { return header_params; }

    // mutators — values are copied into storage_ if setter has no _shallow suffix
    void set_display_name(const string_view &val);
    void set_display_name_shallow(const string_view &val);
    void set_uri_user(const string_view &val);
    void set_uri_user_shallow(const string_view &val);
    void set_uri_host(const string_view &val);
    void set_uri_host_shallow(const string_view &val);
    void set_uri_port(uint16_t val);
    void set_uri_scheme(sip_uri::uri_scheme val);
    void set_uri_scheme_by_name(const string_view &val);

    void set_uri_param(const string_view &name, const string_view &value = {});
    void set_uri_param_shallow(const string_view &name, const string_view &value = {});
    void erase_uri_param(const string_view &name);

    void set_uri_header(const string_view &name, const string_view &value = {});
    void set_uri_header_shallow(const string_view &name, const string_view &value = {});
    void erase_uri_header(const string_view &name);

    void set_header_param(const string_view &name, const string_view &value = {});
    void set_header_param_shallow(const string_view &name, const string_view &value = {});
    void erase_header_param(const string_view &name);

    // aux helpers

    /** @brief patch 'transport' in uri_params
     *  @param newvalue New transport value
     *  @param overwrite Whether to overwrite existent param
     *  @return true if parameter was applied (overwrite true or was no existent param)
     */
    bool patch_uri_transport_param(sip_transport::sip_transport_id new_value, bool overwrite = false);
};
