/*
 * Copyright (C) 2002-2003 Fhg Fokus
 * Copyright (C) 2006 iptego GmbH
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

#include "AmApi.h"
#include "log.h"
#include "AmSession.h"
#include "AmB2BMedia.h" // just because of statistics in reply to OPTIONS

AmDynInvoke::AmDynInvoke() {}
AmDynInvoke::~AmDynInvoke() {}

void AmDynInvoke::invoke(const string &method, const AmArg &args, AmArg &ret)
{
    throw NotImplemented(method);
}

AmDynInvokeFactory::AmDynInvokeFactory(const string &name, const string &version)
    : AmPluginFactory(name, version)
{
}

AmConfigFactory::AmConfigFactory(const string &name, const string &version)
    : AmPluginFactory(name, version)
{
}

AmSessionFactory::AmSessionFactory(const string &name, const string &version)
    : AmPluginFactory(name, version)
{
}

AmSession *AmSessionFactory::onInvite(const AmSipRequest &req, const string &app_name, AmArg &session_params)
{
    WARN(" discarding session parameters to new session.");
    map<string, string> app_params;
    return onInvite(req, app_name, app_params);
}

AmSession *AmSessionFactory::onRefer(const AmSipRequest &req, const string &app_name,
                                     const map<string, string> &app_params)
{
    throw AmSession::Exception(488, "Not accepted here");
}

AmSession *AmSessionFactory::onRefer(const AmSipRequest &req, const string &app_name, AmArg &session_params)
{
    WARN(" discarding session parameters to new session.");
    map<string, string> app_params;
    return onRefer(req, app_name, app_params);
}

int AmSessionFactory::configureModule(AmConfigReader &cfg)
{
    return 0; // mod_conf.readFromConfig(cfg);
}

void AmSessionFactory::configureSession(AmSession *sess)
{
    // SessionTimer::sess->configureSessionTimer(mod_conf);
}

void AmSessionFactory::onOoDRequest(const AmSipRequest &req)
{

    if (req.method == SIP_METH_OPTIONS) {
        replyOptions(req);
        return;
    }

    DBG("sorry, we don't support beginning a new session with "
        "a '%s' message\n",
        req.method.c_str());

    AmSipDialog::reply_error(req, 501, "Not Implemented");
    return;
}

void AmSessionFactory::replyOptions(const AmSipRequest &req)
{
    string hdrs;
    if (!AmConfig.options_transcoder_in_stats_hdr.empty()) {
        string usage;
        B2BMediaStatistics::instance()->reportCodecReadUsage(usage);

        hdrs += AmConfig.options_transcoder_in_stats_hdr + ": ";
        hdrs += usage;
        hdrs += CRLF;
    }
    if (!AmConfig.options_transcoder_out_stats_hdr.empty()) {
        string usage;
        B2BMediaStatistics::instance()->reportCodecWriteUsage(usage);

        hdrs += AmConfig.options_transcoder_out_stats_hdr + ": ";
        hdrs += usage;
        hdrs += CRLF;
    }

    if (!AmConfig.options_supported_hdr_value.empty()) {
        addOptionTags(hdrs, SIP_HDR_SUPPORTED, AmConfig.options_supported_hdr_value);
    }

    if (!AmConfig.options_allow_hdr_value.empty()) {
        addOptionTags(hdrs, SIP_HDR_ALLOW, AmConfig.options_allow_hdr_value);
    }

    // Basic OPTIONS support
    if (AmConfig.options_session_limit && (AmSession::getSessionNum() >= AmConfig.options_session_limit)) {
        // return error code if near to overload
        AmSipDialog::reply_error(req, AmConfig.options_session_limit_err_code,
                                 AmConfig.options_session_limit_err_reason, hdrs);
        return;
    }

    if (AmConfig.shutdown_mode) {
        // return error code if in shutdown mode
        AmSipDialog::reply_error(req, AmConfig.shutdown_mode_err_code, AmConfig.shutdown_mode_err_reason, hdrs);
        return;
    }

    AmSipDialog::reply_error(req, 200, "OK", hdrs);
}

// void AmSessionFactory::postEvent(AmEvent* ev) {
//   ERROR("unhandled Event in %s module", getName().c_str());
//   delete ev;
// }

AmSessionEventHandlerFactory::AmSessionEventHandlerFactory(const string &name, const string &version)
    : AmPluginFactory(name, version)
{
}

bool AmSessionEventHandlerFactory::onInvite(const AmSipRequest &req, AmArg &session_params, AmConfigReader &cfg)
{
    WARN("discarding session parameters for new session.");
    return onInvite(req, cfg);
}


AmLoggingFacility::AmLoggingFacility(const string &name, const string &version, int log_level)
    : AmPluginFactory(name, version)
    , _log_level(log_level)
{
    adjustGlobalLogLevel(); // force consistency with global loglevel
}

void AmLoggingFacility::adjustGlobalLogLevel()
{
    if (_log_level == log_level)
        return;
    int log_level_arg = _log_level;
    if (_log_level > log_level ||         // increase global loglevel
        get_higher_levels(log_level_arg)) // decrease global loglevel if no logging facilities with higher loglevel
    {
        log_level = log_level_arg;
        // INFO("global loglevel adjusted to %d by %s logging facility",log_level,getName().c_str());
    }
}

void AmLoggingFacility::setLogLevel(int log_level_arg)
{
    if (log_level_arg == _log_level)
        return;
    _log_level = FIX_LOG_LEVEL(log_level_arg);
    adjustGlobalLogLevel();
}

void AmLoggingFacility::on_destroy()
{
    // unregister_log_hook(this);
}
