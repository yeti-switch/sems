#pragma once

#include "AmBasicSipDialog.h"
#include "ampi/UACAuthAPI.h"

#include <map>
#include <string>

#include <chrono>
#include <ratio>

using std::map;
using std::string;

class SipSingleProbe : public AmBasicSipEventHandler, public DialogControl, public CredentialHolder {
  public:
    using timep = std::chrono::system_clock::time_point;

  private:
    AmBasicSipDialog dlg;
    UACAuthCred      cred;
    AmSipRequest     req;
    timep            recheck_time;
    timep            last_send_time;
    string           tag;
    string           options_hdrs;
    int              options_flags;
    bool             active_dialog;

    int                       last_reply_code;
    string                    last_reply_reason;
    string                    last_reply_contact;
    std::chrono::milliseconds last_reply_delay;
    string                    last_error_reason;

    // probe fields
    unsigned int         id;
    string               name;
    string               ruri_domain;
    string               ruri_username;
    unsigned int         transport_protocol_id;
    unsigned int         sip_schema_id;
    string               from_uri;
    string               to_uri;
    string               contact_uri;
    string               proxy;
    unsigned int         proxy_transport_protocol_id;
    string               route_set;
    std::chrono::seconds interval;
    string               append_headers;
    string               sip_interface_name;
    string               auth_username;
    string               auth_password;

    void patch_transport(string &uri, int transport_protocol_id);

    string preprocess_append_headers();

  public:
    SipSingleProbe();

    // DialogControl
    AmBasicSipDialog *getDlg() override { return &dlg; }
    // CredentialHolder
    UACAuthCred *getCredentials() override { return &cred; }

    /**
     * @brief initialize using AmArg hash
     * @param a AmArg hash
     * @return true on success
     */
    bool initFromAmArg(const AmArg &a);

    /**
     * @brief process probe. resend request if needed
     * @param now timepoint by the time of the call
     * @return true if prober has to be removed
     */
    bool process(timep &now);

    void onSipReply(const AmSipRequest &req, const AmSipReply &reply, AmBasicSipDialog::Status old_status) override;

    const string &getTag() const { return tag; }
    const string &getName() const { return name; }
    unsigned int  getId() const { return id; }

    void getInfo(AmArg &a);

    void serializeStats(map<string, string> &labels, unsigned long long *values) const;
};

struct ProbersMetricGroup : public StatCountersGroupsInterface {
    static vector<string> metrics_keys_names;
    static vector<string> metrics_help_strings;

    enum metric_keys_idx { PROBE_VALUE_LAST_REPLY_CODE = 0, PROBE_VALUE_LAST_REPLY_DELAY_MS, PROBE_VALUE_MAX };
    struct reg_info {
        map<string, string> labels;
        unsigned long long  values[PROBE_VALUE_MAX];
    };
    vector<reg_info> data;
    int              idx;

    ProbersMetricGroup()
        : StatCountersGroupsInterface(Gauge)
    {
    }

    void add_reg(SipSingleProbe *p)
    {
        data.emplace_back();
        p->serializeStats(data.back().labels, data.back().values);
    }

    void serialize(StatsCountersGroupsContainerInterface::iterate_groups_callback_type callback)
    {
        for (int i = 0; i < PROBE_VALUE_MAX; i++) {
            idx = i;
            // setHelp(metrics_help_strings[idx]);
            callback(metrics_keys_names[idx], *this);
        }
    }

    void iterate_counters(iterate_counters_callback_type callback) override
    {
        for (size_t i = 0; i < data.size(); i++) {
            auto &reg = data[i];
            callback(reg.values[idx], /*0,*/ reg.labels);
        }
    }
};
