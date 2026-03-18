#include "AmShallowUriParser.h"
#include "sip/parse_common.h"
#include "log.h"

// stable storage: list nodes are never moved/invalidated
string_view AmShallowUriParser::own(const string_view &val)
{
    if (val.empty())
        return string_view{};
    storage_.emplace_back(val);
    return storage_.back();
}

void AmShallowUriParser::own_map(kv_container &m)
{
    kv_container tmp;
    for (const auto &[name, value] : m)
        tmp[own(name)] = own(value);
    tmp.swap(m);
}

void AmShallowUriParser::set_map_param(kv_container &m, const string_view &name, const string_view &value)
{
    if (name.empty()) {
        ERROR("attempt to set param with empty name. ignore it");
        return;
    }

    if (auto it = m.find(name); it != m.end()) {
        it->second = own(value);
        return;
    }

    m[own(name)] = own(value);
}

void AmShallowUriParser::set_display_name(const string_view &val)
{
    display_name = own(val);
}

void AmShallowUriParser::set_display_name_shallow(const string_view &val)
{
    display_name = val;
}

void AmShallowUriParser::set_uri_user(const string_view &val)
{
    uri_user = own(val);
}

void AmShallowUriParser::set_uri_user_shallow(const string_view &val)
{
    uri_user = val;
}

void AmShallowUriParser::set_uri_host(const string_view &val)
{
    uri_host = own(val);
}

void AmShallowUriParser::set_uri_host_shallow(const string_view &val)
{
    uri_host = val;
}

void AmShallowUriParser::set_uri_port(uint16_t val)
{
    uri_port = val;
}

void AmShallowUriParser::set_uri_scheme(sip_uri::uri_scheme val)
{
    uri_scheme = val;
}

void AmShallowUriParser::set_uri_scheme_by_name(const string_view &val)
{
    string scheme{ val };
    scheme += ":";
    const char *c = scheme.data();
    uri_scheme    = parse_uri_scheme(c, scheme.length());
}

void AmShallowUriParser::set_uri_param(const string_view &name, const string_view &value)
{
    set_map_param(uri_params, name, value);
}

void AmShallowUriParser::set_uri_param_shallow(const string_view &name, const string_view &value)
{
    uri_params[name] = value;
}

bool AmShallowUriParser::patch_uri_transport_param(sip_transport::sip_transport_id newvalue, bool overwrite)
{
    const static string_view transport_param{ "transport" };

    if (uri_params.contains(transport_param)) {
        if (!overwrite) {
            return false;
        }
        if (newvalue == sip_transport::UDP) {
            erase_uri_param(transport_param);
            return true;
        }
    } else if (newvalue == sip_transport::UDP) {
        return true; // omit transport=udp
    }

    if (!overwrite && uri_params.contains(transport_param))
        return false;

    auto transport_name = transport_str(newvalue);
    if (transport_name.isEmpty()) {
        ERROR("unknown transport_id: %d", newvalue);
        return true;
    }

    set_uri_param_shallow(transport_param, c2stlstrv(transport_name));

    return true;
}

void AmShallowUriParser::erase_uri_param(const string_view &name)
{
    uri_params.erase(name);
}

void AmShallowUriParser::set_uri_header(const string_view &name, const string_view &value)
{
    set_map_param(uri_headers, name, value);
}

void AmShallowUriParser::set_uri_header_shallow(const string_view &name, const string_view &value)
{
    uri_headers[name] = value;
}

void AmShallowUriParser::erase_uri_header(const string_view &name)
{
    uri_headers.erase(name);
}

void AmShallowUriParser::set_header_param(const string_view &name, const string_view &value)
{
    set_map_param(header_params, name, value);
}

void AmShallowUriParser::set_header_param_shallow(const string_view &name, const string_view &value)
{
    header_params[name] = value;
}

void AmShallowUriParser::erase_header_param(const string_view &name)
{
    header_params.erase(name);
}

void AmShallowUriParser::clear()
{
    display_name = {};
    uri_user     = {};
    uri_host     = {};
    uri_port     = 0;
    uri_scheme   = sip_uri::UNKNOWN;
    uri_params.clear();
    uri_headers.clear();
    header_params.clear();
    storage_.clear();
}

static void apply_sip_uri_avp_list(const std::list<sip_avp *> &l, AmShallowUriParser::kv_container &m)
{
    for (auto *avp : l) {
        m[{ avp->name.s, avp->name.len }] =
            avp->value.len ? string_view{ avp->value.s, avp->value.len } : string_view{};
    }
}

void AmShallowUriParser::apply_uri(const sip_uri &parsed)
{
    uri_scheme = parsed.scheme;

    if (parsed.user.len)
        uri_user = string_view(parsed.user.s, parsed.user.len);

    if (parsed.host.len)
        uri_host = string_view(parsed.host.s, parsed.host.len);

    uri_port = parsed.port;

    apply_sip_uri_avp_list(parsed.params, uri_params);
    apply_sip_uri_avp_list(parsed.hdrs, uri_headers);
}

void AmShallowUriParser::apply_nameaddr(const sip_nameaddr &parsed)
{
    apply_uri(parsed.uri);

    if (parsed.name.s && parsed.name.len) {
        display_name = string_view(parsed.name.s, parsed.name.len);
        // trim double-quotes
        if (display_name.starts_with('"'))
            display_name.remove_prefix(1);
        if (display_name.ends_with('"'))
            display_name.remove_suffix(1);
    }

    apply_sip_uri_avp_list(parsed.params, header_params);
}

bool AmShallowUriParser::parse_uri(const string_view &input)
{
    clear();

    sip_uri parsed;
    if (::parse_uri(&parsed, input.data(), input.size()) != 0)
        return false;

    apply_uri(parsed);

    return true;
}

bool AmShallowUriParser::parse_nameaddr(const string_view &input)
{
    clear();

    sip_nameaddr parsed;
    const char  *c = input.data();
    if (parse_nameaddr_uri(&parsed, &c, input.size()) != 0)
        return false;

    apply_nameaddr(parsed);

    return true;
}

void AmShallowUriParser::convert_to_deep_copy()
{
    display_name = own(display_name);
    uri_user     = own(uri_user);
    uri_host     = own(uri_host);

    own_map(uri_headers);
    own_map(uri_params);
    own_map(header_params);
}

void AmShallowUriParser::append_with_canon_uri_str(string &res) const
{
    res += uri_scheme2str(uri_scheme);
    if (uri_scheme == sip_uri::UNKNOWN) {
        ERROR("attempt to serialize URI with unknown scheme. failover to sip:");
        res += "sip";
    }
    res += ":";

    if (uri_scheme == sip_uri::TEL) {
        res += uri_user;
        return;
    }

    if (!uri_user.empty()) {
        res += uri_user;
        res += "@";
    }
    res += uri_host;
    // FIXME: maybe we have to add flag to control default port ommiting
    if (uri_port && uri_port != 5060) {
        res += ":";
        res += std::to_string(uri_port);
    }
}

string AmShallowUriParser::canon_uri_str() const
{
    string res;
    res.reserve(32);
    append_with_canon_uri_str(res);
    return res;
}

void AmShallowUriParser::append_with_uri_str(string &res) const
{
    append_with_canon_uri_str(res);

    for (const auto &[name, value] : uri_params) {
        res += ";";
        res += name;
        if (!value.empty()) {
            res += "=";
            res += value;
        }
    }

    bool first_hdr = true;
    for (const auto &[name, value] : uri_headers) {
        res += first_hdr ? "?" : "&";
        res += name;
        if (!value.empty()) {
            res += "=";
            res += value;
        }
        first_hdr = false;
    }
}

string AmShallowUriParser::uri_str() const
{
    string res;
    res.reserve(64);
    append_with_uri_str(res);
    return res;
}

string AmShallowUriParser::nameaddr_str() const
{
    string res;
    res.reserve(64);

    if (!display_name.empty()) {
        res += "\"";
        res += display_name;
        res += "\" ";
    }

    res += "<";
    append_with_uri_str(res);
    res += ">";

    for (const auto &[name, value] : header_params) {
        res += ";";
        res += name;
        if (!value.empty()) {
            res += "=";
            res += value;
        }
    }

    return res;
}

string AmShallowUriParser::print() const
{
    return nameaddr_str();
}
