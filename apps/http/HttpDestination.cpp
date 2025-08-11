#include "HttpDestination.h"
#include "HttpPostConnection.h"
#include "http_client_cfg.h"
#include "AmLcConfig.h"
#include "AmIdentity.h"
#include "AmUtils.h"
#include "HttpClient.h"
#include "jsonArg.h"
#include "log.h"
#include "defs.h"

#include <algorithm>
#include <vector>
using std::vector;
#include <cstdio>
#include <fstream>
#include <iostream>
#include <unistd.h>


static map<string, vector<string>> http_dest_headers;


int DestinationAction::parse(const string &default_action, cfg_t *cfg)
{
    if (!cfg_size(cfg, PARAM_ACTION_NAME)) {
        action_str = default_action;
    } else {
        action_str = cfg_getstr(cfg, PARAM_ACTION_NAME);
    }

    action = str2Action(action_str);
    if (action == Move) {
        need_data = true;
    } else if (action == Unknown) {
        ERROR("uknown post-upload action: %s", action_str.c_str());
        return -1;
    }

    action_data = cfg_getstr(cfg, PARAM_ACTION_ARGS_NAME);
    if (need_data && action_data.empty()) {
        ERROR("%s: missed action_arg for post upload action: %s", cfg->title, action_str.c_str());
        return -1;
    }

    return 0;
}

void DestinationAction::perform() const
{
    switch (action) {
    case Nothing: break;
    case Remove:
        if (file_path.empty() || !file_exists(file_path))
            break;
        CDBG("remove '%s' after upload or min_file_size condition", file_path.c_str());
        if (0 != std::remove(file_path.c_str())) {
            ERROR("can't remove '%s': %d", file_path.c_str(), errno);
        }
        break;
    case Move:
    {
        if (file_path.empty() || !file_exists(file_path))
            break;
        string destination_path = action_data + "/" + file_basename;
        CDBG("move  '%s'->'%s' after upload or min_file_size condition", file_path.c_str(), destination_path.c_str());
        if (0 != std::rename(file_path.c_str(), destination_path.c_str())) {
            ERROR("can't move '%s'->'%s': %d", file_path.c_str(), destination_path.c_str(), errno);
        }
    } break;
    default: break;
    }
}

void DestinationAction::set_path(const std::string &path)
{
    if (path.empty())
        return;
    file_basename = filename_from_fullpath(path);
    if (file_basename.empty())
        file_basename = path;
    file_path = path;
}


DestinationAction::HttpAction DestinationAction::str2Action(const string &action)
{
    if (action == ACTION_REMOVE_VALUE) {
        return Remove;
    } else if (action == ACTION_NOTHING_VALUE) {
        return Nothing;
    } else if (action == ACTION_MOVE_VALUE) {
        return Move;
    } else if (action == ACTION_REQUEUE_VALUE) {
        return Requeue;
    } else {
        return Unknown;
    }
}

HttpCodesMap::HttpCodesMap()
{
    bzero(codes, sizeof(codes));
}

int HttpCodesMap::parse(cfg_t *cfg)
{
    if (!cfg_size(cfg, PARAM_SUCCESS_CODES_NAME)) {
        // 2xx
        memset(codes + 200, true, sizeof(bool) * 100);
        return 0;
    }

    for (unsigned int i = 0; i < cfg_size(cfg, PARAM_SUCCESS_CODES_NAME); i++) {
        string mask = cfg_getnstr(cfg, PARAM_SUCCESS_CODES_NAME, i);
        if (mask.find('x') != string::npos) {
            string mins = mask, maxs = mask;
            int    min, max;
            std::replace(mins.begin(), mins.end(), 'x', '0');
            std::replace(maxs.begin(), maxs.end(), 'x', '9');
            if (!str2int(mins, min)) {
                ERROR("can't convert bottom border value %s for mask %s to int.", mins.c_str(), mask.c_str());
                return -1;
            }
            if (!str2int(maxs, max)) {
                ERROR("can't convert upper border value %s for mask %s to int", maxs.c_str(), mask.c_str());
                return -1;
            }
            for (int i = min; i <= max; i++)
                codes[i] = true;
        } else {
            int i;
            if (!str2int(mask, i)) {
                ERROR("can't convert mask %s to int", mask.c_str());
                return -1;
            }
            codes[i] = true;
        }
    }
    return 0;
}

void HttpCodesMap::dump(AmArg &ret) const
{
    bool within_interval = false;
    int  interval_start  = 0;

    ret.assertArray();
    for (int i = 0; i < 1000; i++) {
        if (!within_interval) {
            if (!codes[i]) {
                // continue of the gap
                continue;
            }
            // new interval
            within_interval = true;
            interval_start  = i;
        } else {
            if (codes[i]) {
                // interval continues
                continue;
            }
            // interval end
            within_interval = false;
            ret.push(AmArg());
            if (interval_start == (i - 1)) {
                ret.back() = interval_start;
            } else {
                AmArg &interval = ret.back();
                interval.push(interval_start);
                interval.push(i - 1);
            }
        }
    }
}

bool HttpCodesMap::operator()(long int code) const
{
    if (code > 0 && code < 1000)
        return codes[code];
    else
        return false;
}

HttpDestination::HttpDestination(const string &name)
    : auth_type(AuthType_Unknown)
    , is_auth_destination(false)
    , http2_tls(false)
    , min_file_size(0)
    , max_reply_size(0)
    , count_failed_events(stat_group(Gauge, MOD_NAME, "failed_events").addAtomicCounter().addLabel("destination", name))
    , count_connection(
          stat_group(Gauge, MOD_NAME, "active_connections").addAtomicCounter().addLabel("destination", name))
    , resend_count_connection(
          stat_group(Gauge, MOD_NAME, "active_resend_connections").addAtomicCounter().addLabel("destination", name))
    , count_pending_events(
          stat_group(Gauge, MOD_NAME, "pending_events").addAtomicCounter().addLabel("destination", name))
    , requests_processed(
          stat_group(Counter, MOD_NAME, "requests_processed").addAtomicCounter().addLabel("destination", name))
    , requests_failed(stat_group(Counter, MOD_NAME, "requests_failed").addAtomicCounter().addLabel("destination", name))
{
}

HttpDestination::~HttpDestination()
{
    while (!events.empty()) {
        delete events.front();
        events.pop_front();
    }
}
extern long parse_size(const string &size);


extern int http_dest_header_func(cfg_t *cfg, cfg_opt_t * /*opt*/, int argc, const char **argv)
{
    if (argc != 2) {
        ERROR("header(): unexpected option args count %d, "
              "expected format: header(header_name, header_value)",
              argc);
        return -1;
    }

    string header = string(argv[0]) + ": ";
    header += argv[1];

    http_dest_headers[cfg_title(cfg)].emplace_back(header);
    return 0;
}

int HttpDestination::parse(const string &name, cfg_t *cfg, const DefaultValues &values, bool is_auth = false)
{
    bool need_destination = false;

    if (is_auth) {
        AmLcConfig::instance().getMandatoryParameter(cfg, PARAM_AUTH_TYPE, auth_type_str);
        is_auth_destination = is_auth;
        auth_type           = str2AuthType(auth_type_str);

        switch (auth_type) {
        case AuthType_Firebase_oauth2:
        {
            std::ifstream     ifs;
            std::stringstream stream;

            jwt_kid          = cfg_getstr(cfg, PARAM_AUTH_JWT_KIT);
            jwt_iss          = cfg_getstr(cfg, PARAM_AUTH_JWT_ISS);
            key_file         = cfg_getstr(cfg, PARAM_AUTH_PRIVATE_KEY);
            token_lifetime   = cfg_getint(cfg, PARAM_AUTH_TOKEN_LIFETIME);
            need_destination = true;

            if (key_file.empty() || (ifs.open(key_file), !ifs.is_open())) {
                ERROR("can't access the private_key file %s: %m", key_file.c_str());
                return -1;
            }

            stream << ifs.rdbuf();
            key_data = stream.str();
            ifs.close();
            break;
        }
        case AuthType_s3:
        {
            access_key = cfg_getstr(cfg, PARAM_AUTH_ACCESS_KEY);
            secret_key = cfg_getstr(cfg, PARAM_AUTH_SECRET_KEY);
            break;
        }
        default:;
        }
    } else {
        need_destination = true;
    }

    if (!need_destination) {
        mode = Unknown;
        return 0;
    }

    AmLcConfig::instance().getMandatoryParameter(cfg, PARAM_MODE_NAME, mode_str);
    mode = str2Mode(mode_str);
    if (mode == Unknown) {
        ERROR("%s: uknown mode: %s", name.c_str(), mode_str.c_str());
        return -1;
    }

    auth_required   = cfg_getstr(cfg, PARAM_AUTH_NAME);
    auth_usrpwd     = cfg_getstr(cfg, PARAM_AUTH_USRPWD);
    attempts_limit  = cfg_getint(cfg, PARAM_REQUEUE_LIMIT_NAME);
    http2_tls       = cfg_getbool(cfg, PARAM_HTTP2_TLS);
    certificate     = cfg_getstr(cfg, PARAM_CERT);
    certificate_key = cfg_getstr(cfg, PARAM_CERT_KEY);

    if (!certificate.empty() && ::access(certificate.c_str(), F_OK | R_OK) != 0) {
        ERROR("can't access the certificate file %s: %m", certificate.c_str());
        return -1;
    }

    if (!certificate_key.empty() && ::access(certificate_key.c_str(), F_OK | R_OK) != 0) {
        ERROR("can't access the certificate_key file %s: %m", certificate_key.c_str());
        return -1;
    }

    if (http_dest_headers.count(name))
        http_headers.swap(http_dest_headers[name]);

    for (unsigned int i = 0; i < cfg_size(cfg, PARAM_URL_NAME); i++) {
        string url_ = cfg_getnstr(cfg, PARAM_URL_NAME, i);
        url.push_back(url_);
    }
    if (mode != Get && url.empty()) {
        ERROR("missed url for destination %s", name.c_str());
        return -1;
    }

    if (url.empty())
        max_failover_idx = 0;
    else
        max_failover_idx = url.size() - 1;

    source_address = cfg_getstr(cfg, PARAM_SOURCE_ADDRESS_NAME);

    if (succ_codes.parse(cfg)) {
        ERROR("can't parse succ codes map");
        return -1;
    }

    if (!cfg_size(cfg, SECTION_ON_SUCCESS_NAME)) {
        ERROR("absent post_upload action");
        return -1;
    }

    cfg_t *saction = cfg_getsec(cfg, SECTION_ON_SUCCESS_NAME);
    if (succ_action.parse(ACTION_REMOVE_VALUE, saction)) {
        ERROR("can't parse post_upload action");
        return -1;
    }

    if (!cfg_size(cfg, SECTION_ON_FAIL_NAME)) {
        ERROR("absent failed_upload action");
        return -1;
    }

    cfg_t *faction = cfg_getsec(cfg, SECTION_ON_FAIL_NAME);
    if (fail_action.parse(ACTION_REMOVE_VALUE, faction)) {
        ERROR("can't parse failed_upload action");
        return -1;
    }

    if (succ_action.requeue()) {
        ERROR("forbidden action 'requeue' for succ action");
        return -1;
    }

    if (mode == Post) {
        if (!cfg_size(cfg, PARAM_CONTENT_TYPE_NAME)) {
            ERROR("absent 'content_type' for post mode");
            return -1;
        }
        content_type = cfg_getstr(cfg, PARAM_CONTENT_TYPE_NAME);
    }

    if (mode == Put && cfg_size(cfg, PARAM_CONTENT_TYPE_NAME))
        content_type = cfg_getstr(cfg, PARAM_CONTENT_TYPE_NAME);

    if (cfg_size(cfg, PARAM_CONNECTION_LIMIT_NAME))
        connection_limit = cfg_getint(cfg, PARAM_CONNECTION_LIMIT_NAME);
    else
        connection_limit = values.connection_limit;
    if (!connection_limit) {
        ERROR("connection limit cannot equal zero");
        return -1;
    }

    if (cfg_size(cfg, PARAM_RESEND_CONNECTION_LIMIT_NAME))
        resend_connection_limit = cfg_getint(cfg, PARAM_RESEND_CONNECTION_LIMIT_NAME);
    else
        resend_connection_limit = values.resend_connection_limit;
    if (!resend_connection_limit) {
        ERROR("resend connection limit cannot equal zero");
        return -1;
    }

    if (cfg_size(cfg, PARAM_RESEND_QUEUE_MAX_NAME))
        resend_queue_max = cfg_getint(cfg, PARAM_RESEND_QUEUE_MAX_NAME);
    else
        resend_queue_max = values.resend_queue_max;
    if (!resend_queue_max) {
        ERROR("resend queue max cannot equal zero");
        return -1;
    }

    if (cfg_size(cfg, PARAM_MIN_FILE_SIZE_NAME)) {
        min_file_size = parse_size(cfg_getstr(cfg, PARAM_MIN_FILE_SIZE_NAME));
    }

    if (cfg_size(cfg, PARAM_MAX_REPLY_SIZE_NAME)) {
        max_reply_size = parse_size(cfg_getstr(cfg, PARAM_MAX_REPLY_SIZE_NAME));
    }

    return 0;
}

void HttpDestination::dump(const string &key) const
{
    string url_list;
    for (auto &url_ : url) {
        if (!url_list.empty())
            url_list += ",";
        url_list += url_;
    }
    string source_addr;
    if (!source_address.empty()) {
        source_addr = ", source_address = ";
        source_addr += source_address;
    }
    string post_upload = ", post_upload = ";
    if (!succ_action.str().empty()) {
        post_upload += succ_action.str() + " " + succ_action.data();
    } else if (!finish_action.str().empty()) {
        post_upload += finish_action.str() + " " + finish_action.data();
    }
    string failed_upload;
    if (!fail_action.str().empty()) {
        failed_upload = ", failed_upload = ";
        failed_upload += fail_action.str() + " " + fail_action.data();
    }
    DBG("destination %s: %s %s%s%s%s", key.c_str(), mode_str.c_str(), url_list.c_str(), source_addr.c_str(),
        post_upload.c_str(), failed_upload.c_str());
}

void HttpDestination::dump(const string &, AmArg &ret) const
{
    string url_list;
    for (auto &url_ : url) {
        if (!url_list.empty())
            url_list += ",";
        url_list += url_;
    }
    ret["http2_tls"] = http2_tls;
    ret["mode"]      = mode_str.c_str();
    ret["url"]       = url_list;

    if (!access_token.empty())
        ret["access_token"] = access_token;

    if (!auth_required.empty())
        ret["auth"] = auth_required;

    if (!auth_usrpwd.empty())
        ret["auth_usrpwd"] = auth_usrpwd;

    if (!certificate.empty())
        ret["certificate"] = certificate.c_str();
    if (!certificate_key.empty())
        ret["certificate_key"] = certificate_key.c_str();
    if (http_headers.size()) {
        auto &_headers = ret["headers"];
        for (const auto &h : http_headers)
            _headers.push(h);
    }

    ret["source_address"] = source_address.c_str();
    ret["succ_action"]    = succ_action.str();
    if (succ_action.has_data()) {
        ret["action_data"] = succ_action.data();
    }
    ret["failed_action"] = fail_action.str();
    if (fail_action.has_data()) {
        ret["failed_action_data"] = fail_action.str();
    }
    if (mode == Post && !content_type.empty()) {
        ret["content_type"] = content_type;
    }
    if (!access_key.empty()) {
        ret["access_key"] = access_key;
    }
    if (!secret_key.empty()) {
        ret["secret_key"] = secret_key;
    }
    ret["attempts_limit"]          = static_cast<int>(attempts_limit);
    ret["resend_queue_max"]        = static_cast<int>(resend_queue_max);
    ret["connection_limit"]        = static_cast<int>(resend_connection_limit);
    ret["resend_connection_limit"] = static_cast<int>(connection_limit);
    succ_codes.dump(ret["succ_codes"]);
}


HttpDestination::AuthType HttpDestination::str2AuthType(const string &type)
{
    if (type == AUTH_TYPE_FB_OA2_VALUE) {
        return AuthType_Firebase_oauth2;
    }

    if (type == AUTH_TYPE_S3_VALUE) {
        return AuthType_s3;
    }

    return AuthType_Unknown;
}


HttpDestination::Mode HttpDestination::str2Mode(const string &mode)
{
    if (mode == MODE_PUT_VALUE) {
        return Put;
    } else if (mode == MODE_POST_VALUE) {
        return Post;
    } else if (mode == MODE_GET_VALUE) {
        return Get;
    }
    return Unknown;
}

void HttpDestination::addEvent(HttpEvent *event)
{
    if (event->attempt) {
        events.push_back(event);
        count_failed_events.inc();
    } else {
        events.push_front(event);
        count_pending_events.inc();
    }
}

void HttpDestination::on_finish(bool failed, const string &response)
{
    AmArg res;

    if (!is_auth_destination)
        return;

    if (failed || response.empty())
        return;

    if (!json2arg(response, res)) {
        ERROR("failed deserialize json payload: '%s'", response.c_str());
        return;
    }

    if (!res.hasMember("access_token") || !isArgCStr(res["access_token"])) {
        ERROR("access_token as string expected");
        return;
    }

    access_token = res["access_token"].asCStr();

    expires = res.hasMember("expires_in") && isArgInt(res["expires_in"]) ? res["expires_in"].asInt() : token_lifetime;

    gettimeofday(&token_created_at, NULL);
}

void HttpDestination::credentials_refresh(HttpClient *client, const string &name)
{
    Botan::DataSource_Memory            ds(key_data);
    std::unique_ptr<Botan::Private_Key> pk = Botan::PKCS8::load_key(ds);
    AmIdentity                          identity;
    AmArg                               data;

    data["assertion"]  = identity.generate_firebase_assertion(pk.get(), token_lifetime, jwt_kid, jwt_iss);
    data["grant_type"] = "urn:ietf:params:oauth:grant-type:jwt-bearer";

    HttpPostEvent *ev = new HttpPostEvent(name, arg2json(data), string());
    client->on_post_request(ev);
    delete ev;
}

void HttpDestination::auth_on_timer_event(HttpClient *client, const std::string &name)
{
    if (auth_type != AuthType_Firebase_oauth2)
        return;

    if (!access_token.empty()) {

        struct timeval delta, now;

        gettimeofday(&now, nullptr);
        timersub(&now, &token_created_at, &delta);

        auto ttl = delta.tv_sec + 5;

        if (ttl < expires)
            return;
    }

    credentials_refresh(client, name);
}

void HttpDestination::send_failed_events(HttpClient *client)
{
    HttpEvent *event;

    if (events.empty())
        return;

    unsigned int count_will_send = (resend_count_connection.get() < resend_connection_limit)
                                       ? resend_connection_limit - resend_count_connection.get()
                                       : 0;
    while (!events.empty() && count_will_send && (event = events.back()) && event->attempt) {
        events.pop_back();


        HttpUploadEvent *upload_event = dynamic_cast<HttpUploadEvent *>(event);
        if (upload_event)
            client->on_upload_request(upload_event);
        HttpPostEvent *post_event = dynamic_cast<HttpPostEvent *>(event);
        if (post_event)
            client->on_post_request(post_event);
        HttpPostMultipartFormEvent *multipart_event = dynamic_cast<HttpPostMultipartFormEvent *>(event);
        if (multipart_event)
            client->on_multpart_form_request(multipart_event);
        HttpGetEvent *get_event = dynamic_cast<HttpGetEvent *>(event);
        if (get_event)
            client->on_get_request(get_event);
        count_failed_events.dec();
        count_will_send--;
        delete event;
    }
}

void HttpDestination::send_postponed_events(HttpClient *client)
{
    HttpEvent   *event;
    unsigned int count_will_send = connection_limit - count_connection.get();
    while (!events.empty() && count_will_send && (event = events.front()) && !event->attempt) {
        events.pop_front();

        client->process_http_event(event);

        count_pending_events.dec();
        count_will_send--;
        delete event;
    }
}

bool HttpDestination::check_queue()
{
    return resend_queue_max && count_failed_events.get() >= resend_queue_max;
}

void HttpDestination::showStats(AmArg &ret)
{
    ret["pending_events"]            = (int)count_pending_events.get();
    ret["failed_events"]             = (int)count_failed_events.get();
    ret["active_connections"]        = (int)count_connection.get();
    ret["active_resend_connections"] = (int)resend_count_connection.get();
    ret["requests_processed"]        = static_cast<unsigned long>(requests_processed.get());
    ret["requests_failed"]           = static_cast<unsigned long>(requests_failed.get());
}

int HttpDestinationsMap::configure_destination(const string &name, cfg_t *cfg, const DefaultValues &values,
                                               bool is_auth = false)
{
    HttpDestination d(name);
    if (d.parse(name, cfg, values, is_auth)) {
        return -1;
    }
    std::pair<HttpDestinationsMap::iterator, bool> ret;
    ret = insert(std::pair<string, HttpDestination>(name, d));
    if (ret.second == false) {
        ERROR("duplicate upload destination: %s", name.c_str());
        return -1;
    }
    return 0;
}

int HttpDestinationsMap::configure(cfg_t *cfg, DefaultValues &values)
{
    for (unsigned int i = 0; i < cfg_size(cfg, SECTION_AUTH_NAME); i++) {
        cfg_t *auth = cfg_getnsec(cfg, SECTION_AUTH_NAME, i);
        if (configure_destination(auth->title, auth, values, true)) {
            ERROR("can't configure auth destination %s", auth->title);
            return -1;
        }
    }

    for (unsigned int i = 0; i < cfg_size(cfg, SECTION_DEST_NAME); i++) {
        cfg_t *dest = cfg_getnsec(cfg, SECTION_DEST_NAME, i);
        if (configure_destination(dest->title, dest, values)) {
            ERROR("can't configure destination %s", dest->title);
            return -1;
        }
    }
    return 0;
}

void HttpDestinationsMap::dump()
{
    for (HttpDestinationsMap::const_iterator i = begin(); i != end(); i++)
        i->second.dump(i->first);
}

void HttpDestinationsMap::dump(AmArg &ret)
{
    ret.assertStruct();
    for (HttpDestinationsMap::const_iterator i = begin(); i != end(); i++)
        i->second.dump(i->first, ret[i->first]);
}

bool HttpDestinationsMap::need_requeue()
{
    for (HttpDestinationsMap::const_iterator i = begin(); i != end(); i++) {
        if (i->second.need_requeue())
            return true;
    }
    return false;
}
