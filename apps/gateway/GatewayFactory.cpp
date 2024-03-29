
#include "GatewayFactory.h"
#include "GWSession.h"
#include "mISDNStack.h"
#include "AmUtils.h"
#include "AmLcConfig.h"
#include "log.h"

EXPORT_SESSION_FACTORY(GatewayFactory,MODULE_NAME);

AmConfigReader gwconf;

GatewayFactory::GatewayFactory(const string& _app_name)
  : AmSessionFactory(_app_name)
{
    INFO("GatewayFactory constructor");

	if(mISDNStack::GetPortInfo()!=OK) {
	    ERROR("mISDNStack::GetPortInfo failed");
	    return;
	}
	if(!mISDNStack::instance()){
	    ERROR("mISDN stack not initialized.");
	    return;
	}
}

int GatewayFactory::onLoad()
{
    INFO("gateway version %s loading (mISDN) ...", GW_VERSION);
    if (gwconf.loadFile(AmConfig.configs_path + string(MODULE_NAME)+ ".conf")) {
//  if (gwconf.loadFile(AmConfig.configs_path +"gateway.conf")) {
        DBG("cant load conf file %s/%s.conf",AmConfig.configs_path.c_str(),MODULE_NAME);
        exit(-1);
    }
    configureModule(gwconf);
    auth_enable     = (gwconf.getParameter("auth_enable", "no")=="yes");
    auth_realm      = gwconf.getParameter("auth_realm", "");
    auth_user       = gwconf.getParameter("auth_user",  "");
    auth_pwd        = gwconf.getParameter("auth_pwd", "");
    if(auth_enable) {
        uac_auth_f = AmPlugIn::instance()->getFactory4Seh("uac_auth");
	DBG("uac_auth_f == 0x%.16lX",(unsigned long)uac_auth_f);
    } else uac_auth_f=NULL;
    return 0;
}

AmSession* GatewayFactory::onInvite(const AmSipRequest& req)
{
    INFO("IsdnGatewayFactory::onInvite()");
        if (req.user.empty())
                throw AmSession::Exception(500,"gateway: internal error, user is empty\n");
        DBG("received onInvite for outgoing call!");
        GWSession* session=new GWSession(auth_realm,auth_user,auth_pwd);
//        if (uac_auth_f != NULL) {
//            DBG("UAC Auth enabled for session.");
//            AmSessionEventHandler* h = uac_auth_f->getHandler(session);
//            if (h != NULL )	session->addHandler(h);
//        }
	DBG("calling (mISDNStack::instance())->placeCall(req, session, tonumber, fromnumber);");
	int ret=(mISDNStack::instance())->placeCall(req, session, req.user, req.from);
	if(ret==FAIL) {
	    ERROR("mISDNStack::placeCall failed");
	    return NULL;
	}
        DBG("now returning GatewayDialog");
        return session;
}
// this is session creator for incoming calls
//call actually starts in isdn module as CC_SETUP, and there GWSession::CallFromOutSide is executed
// which calls AmUac::dialout which in turn calls this function
//session pointer is returned back so we can finish filling object with data there 
AmSession* GatewayFactory::onInvite(const AmSipRequest& req, AmArg& session_params)
{
    INFO("GatewayFactory::onInvite(with args)");
//    GWCall* call = new GWCall();
    GWSession* session=new GWSession(auth_realm,auth_user,auth_pwd);
    DBG("GatewayFactory::onInvite(with args) session=%p",session);
    if (uac_auth_f != NULL) {
        DBG("UAC Auth enabled for session.");
        AmSessionEventHandler* h = uac_auth_f->getHandler(session);
        if (h != NULL )	session->addHandler(h);
    }
    return session;
}

GatewayFactory::~GatewayFactory()
{
        DBG("gateway: destructor of GatewayFactory: cleaning up.");
//        mISDNStack::instance()->shutdown();
        delete(mISDNStack::instance());
}



/** EMACS **
 * Local variables:
 * mode: c++
 * c-basic-offset: 4
 * End:
 */
