/*
 * Copyright (C) 2009 IPTEGO GmbH
 *
 * This file is part of SEMS, a free SIP media server.
 *
 * SEMS is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
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

#include "UrlCatcher.h"
#include "AmUtils.h"
#include "AmPlugIn.h"
#include "AmLcConfig.h"

#include "sems.h"
#include "log.h"

#include <stdlib.h>

#define MOD_NAME "urlcatcher"
#define DEFAULT_EXEC_CMD "firefox"

EXPORT_SESSION_FACTORY(UrlCatcherFactory,MOD_NAME);

string UrlCatcherFactory::ExecCmd;

UrlCatcherFactory::UrlCatcherFactory(const string& _app_name)
  : AmSessionFactory(_app_name)
{
}

int UrlCatcherFactory::onLoad()
{

  AmConfigReader cfg;
  if(cfg.loadFile(AmConfig.configs_path + string(MOD_NAME ".conf"))) {
    ExecCmd = DEFAULT_EXEC_CMD;
    return 0;
  }

  ExecCmd = cfg.getParameter("url_exec_cmd", DEFAULT_EXEC_CMD);
  INFO("UrlCatcher loaded.Exec cmd = '%s'", ExecCmd.c_str());
  return 0;
}


AmSession* UrlCatcherFactory::onInvite(const AmSipRequest& req, const string& app_name,
				       const map<string,string>& app_params)
{
  AmSdp sdp;
  if (sdp.parse(req.body.c_str())) {
    ERROR("SDP parsing error");
    throw AmSession::Exception(404, "Not Found Here (SDP parse error)");
  }

  INFO("SDP URI= '%s'", sdp.uri.c_str());
  if (sdp.uri.empty())
    throw AmSession::Exception(404, "Not Found Here (No Call URI found)");

  int res = system((UrlCatcherFactory::ExecCmd + " \""+sdp.uri+"\"").c_str());
  if (res == -1) {
    ERROR("executing system command '%s'", 
	  (UrlCatcherFactory::ExecCmd + " \""+sdp.uri+"\"").c_str());
  } else {
    DBG("command returned code %d", res);
  }

  throw AmSession::Exception(404, "Not Found Here (but I got your URL)");
}

