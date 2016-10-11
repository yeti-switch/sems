#ifndef _RegEvents_H_
#define _RegEvents_H_

struct SessionLocation
{
	string id;

	string callid;
	string from;
	string to;
	string user;
	string user_agent;
	string contact;

	string transport_proto;
	string transport_local_ip;
	u_int16 transport_local_port;
	string transport_local_if;
	string transport_remote_ip;
	u_int16 transport_remote_port;

	time_t created;
	time_t updated;
	time_t expires;

	SessionLocation(const AmSipRequest &req);
	void setExpires(long _expires);
	void setUsername(string &username);
	bool ToHash(std::map<std::string, std::string> &rhash);
};

#define E_REGISTER           117

class RegisterEvent
		:public AmEvent
{
public:
	SessionLocation sessionLocation;
	RegisterEvent(SessionLocation &sl):
			AmEvent(E_REGISTER),
			sessionLocation(sl)
	{ }
};

#endif
